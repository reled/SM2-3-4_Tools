# coding=utf-8

import qt_sm2_key_gen as kg
import qt_sm2_crypt as sm2_run
import qt_sm3_crypt as sm3_run
import qt_sm4_crypt as sm4_run

import os, time
import PySide2
from PySide2.QtUiTools import QUiLoader
from PySide2.QtWidgets import QApplication, QFileDialog, QMainWindow

dirname = os.path.dirname(PySide2.__file__)
plugin_path = os.path.join(dirname, 'plugins', 'platforms')
os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = plugin_path
print(plugin_path)


class Encrypt:
    def __init__(self):
        self.ui = QUiLoader().load('encrypt.ui')

        # sm2
        self.ui.sm2_log_clear_button.clicked.connect(self.sm2_log_clear)

        self.ui.sm2_pub_file_button.clicked.connect(self.choose_pub_file)
        self.ui.sm2_keygen_button.clicked.connect(self.keygen)
        self.ui.sm2_pri_file_button.clicked.connect(self.choose_pri_file)

        self.ui.sm2_enc_file_button.clicked.connect(self.sm2_choose_enc_file)
        self.ui.sm2_enc_plaintext_clear_button.clicked.connect(self.plain_clear)
        self.ui.sm2_cipher_store_file_button.clicked.connect(self.choose_cipher_store_file)
        self.ui.sm2_enc_button.clicked.connect(self.sm2_enc)

        self.ui.sm2_dec_file_button.clicked.connect(self.sm2_choose_dec_file)
        self.ui.sm2_dec_ciphertext_clear_button.clicked.connect(self.cipher_clear)
        self.ui.sm2_plain_store_file_button.clicked.connect(self.choose_plain_store_file)
        self.ui.sm2_dec_button.clicked.connect(self.sm2_dec)

        self.ui.sm2_sign_file_button.clicked.connect(self.choose_sign_file)
        self.ui.sm2_sign_sign_store_file_button.clicked.connect(self.choose_sign_sign_store_file)
        self.ui.sm2_sign_button.clicked.connect(self.sign)

        self.ui.sm2_verify_file_button.clicked.connect(self.sm2_choose_verify_file)
        self.ui.sm2_verify_sign_file_button.clicked.connect(self.choose_verify_sign_store_file)
        self.ui.sm2_verify_button.clicked.connect(self.sm2_verify)

        # sm3
        self.ui.sm3_log_clear_button.clicked.connect(self.sm3_log_clear)

        self.ui.sm3_hash_file_button.clicked.connect(self.choose_hash_file)
        self.ui.sm3_store_hash_file_button.clicked.connect(self.choose_store_hash_file)
        self.ui.sm3_hash_button.clicked.connect(self.hash)

        self.ui.sm3_verify_file_button.clicked.connect(self.sm3_choose_verify_file)
        self.ui.sm3_verify_hash_file_button.clicked.connect(self.choose_verify_hash_file)
        self.ui.sm3_verify_button.clicked.connect(self.sm3_verify)

        # sm4
        self.ui.sm4_log_clear_button.clicked.connect(self.sm4_log_clear)

        self.ui.sm4_enc_plain_file_button.clicked.connect(self.sm4_choose_enc_file)
        self.ui.sm4_enc_store_cipher_file_button.clicked.connect(self.choose_store_cipher_file)
        self.ui.sm4_enc_button.clicked.connect(self.sm4_enc)

        self.ui.sm4_dec_cipher_file_button.clicked.connect(self.sm4_choose_dec_file)
        self.ui.sm4_dec_store_plain_file_button.clicked.connect(self.choose_store_plain_file)
        self.ui.sm4_dec_button.clicked.connect(self.sm4_dec)

    # sm2
    def sm2_log_clear(self):
        self.ui.sm2_log.clear()

    def choose_pub_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm2_pub_file_linetext.setText(FileDirectory[0])

    def keygen(self):
        kg.key_write("private_key", "public_key")
        self.ui.sm2_log.append("已在当前目录下产生公钥文件public_key与私钥文件private_key！")

    def choose_pri_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm2_pri_file_linetext.setText(FileDirectory[0])

    def sm2_choose_enc_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm2_enc_file_linetext.setText(FileDirectory[0])

    def plain_clear(self):
        self.ui.sm2_enc_plaintext.clear()

    def choose_cipher_store_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getExistingDirectory(mainwindow, "选择文件")
        self.ui.sm2_cipher_store_file_linetext.setText(FileDirectory)

    def sm2_enc(self):
        public_key_path = str(self.ui.sm2_pub_file_linetext.text())
        private_key_path = str(self.ui.sm2_pri_file_linetext.text())
        if not os.path.exists(public_key_path):
            self.ui.sm2_log.append("公钥文件不存在，请重新输入！")
        if not os.path.exists(private_key_path):
            self.ui.sm2_log.append("私钥文件不存在，请重新输入！")
        private_key = sm2_run.file_read(private_key_path)
        public_key = sm2_run.file_read(public_key_path)
        data_path = str(self.ui.sm2_enc_file_linetext.text())
        data = str(self.ui.sm2_enc_plaintext.toPlainText())

        if data_path and data:
            self.ui.sm2_log.append("加密文件路径和明文不能同时存在！")
        elif not data_path and not data:
            self.ui.sm2_log.append("加密文件路径和明文不能同时为空！")
        else:
            if data_path:
                if not os.path.exists(data_path):
                    self.ui.sm2_log.append("加密文件不存在，请重新输入！")
                data = sm2_run.file_read(data_path)
                start = time.perf_counter()
                cipher_hex = sm2_run.SM2_en(private_key, public_key, data)
                end = time.perf_counter()
                self.ui.sm2_log.append("加密完成！耗时{:.6}s".format(end - start))
                self.ui.sm2_log.append("文件已保存！")
                store_path = str(self.ui.sm2_cipher_store_file_linetext.text()) + '//' + str(
                    self.ui.sm2_cipher_filename_linetext.text())
                sm2_run.file_write(store_path, cipher_hex)
            else:
                start = time.perf_counter()
                cipher_hex = sm2_run.SM2_en(private_key, public_key, data)
                end = time.perf_counter()
                self.ui.sm2_log.append("加密完成！耗时{:.6}s".format(end - start))
                self.ui.sm2_log.append(f"密文为:\n{cipher_hex}")

    def sm2_choose_dec_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm2_dec_file_linetext.setText(FileDirectory[0])

    def cipher_clear(self):
        self.ui.sm2_dec_ciphertext.clear()

    def choose_plain_store_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getExistingDirectory(mainwindow, "选择文件")
        self.ui.sm2_plain_store_file_linetext.setText(FileDirectory)

    def sm2_dec(self):
        public_key_path = str(self.ui.sm2_pub_file_linetext.text())
        private_key_path = str(self.ui.sm2_pri_file_linetext.text())
        if not os.path.exists(public_key_path):
            self.ui.sm2_log.append("公钥文件不存在，请重新输入！")
        if not os.path.exists(private_key_path):
            self.ui.sm2_log.append("私钥文件不存在，请重新输入！")
        private_key = sm2_run.file_read(private_key_path)
        public_key = sm2_run.file_read(public_key_path)
        data_path = str(self.ui.sm2_dec_file_linetext.text())
        data = str(self.ui.sm2_dec_ciphertext.toPlainText())

        if data_path and data:
            self.ui.sm2_log.append("解密文件路径和密文不能同时存在！")
        elif not data_path and not data:
            self.ui.sm2_log.append("解密文件路径和密文不能同时为空！")
        else:
            if data_path:
                if not os.path.exists(data_path):
                    self.ui.sm2_log.append("解密文件不存在，请重新输入！")
                data = sm2_run.file_read(data_path)
                try:
                    start = time.perf_counter()
                    plaintext = sm2_run.SM2_de(private_key, public_key, data)
                    end = time.perf_counter()
                    self.ui.sm2_log.append("解密完成！耗时{:.6}s".format(end - start))
                    self.ui.sm2_log.append("文件已保存！")
                    store_path = str(self.ui.sm2_plain_store_file_linetext.text()) + '//' + str(
                        self.ui.sm2_plain_filename_linetext.text())
                    sm2_run.file_write(store_path, plaintext)
                except:
                    self.ui.sm2_log.append("解密失败，请检查私钥是否正确！")
            else:
                try:
                    start = time.perf_counter()
                    plaintext = sm2_run.SM2_de(private_key, public_key, data)
                    end = time.perf_counter()
                    self.ui.sm2_log.append("解密完成！耗时{:.6}s".format(end - start))
                    self.ui.sm2_log.append(f"密文为:\n{plaintext}")
                except:
                    self.ui.sm2_log.append("解密失败，请检查私钥是否正确！")

    def choose_sign_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm2_sign_file_linetext.setText(FileDirectory[0])

    def choose_sign_sign_store_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getExistingDirectory(mainwindow, "选择文件")
        self.ui.sm2_sign_sign_store_file_linetext.setText(FileDirectory)

    def sign(self):
        public_key_path = str(self.ui.sm2_pub_file_linetext.text())
        private_key_path = str(self.ui.sm2_pri_file_linetext.text())
        data_path = str(self.ui.sm2_sign_file_linetext.text())
        if not os.path.exists(public_key_path):
            self.ui.sm2_log.append("公钥文件不存在，请重新输入！")
        if not os.path.exists(private_key_path):
            self.ui.sm2_log.append("私钥文件不存在，请重新输入！")
        if not os.path.exists(data_path):
            self.ui.sm2_log.append("要进行签名的文件不存在，请重新输入！")
        private_key = sm2_run.file_read(private_key_path)
        public_key = sm2_run.file_read(public_key_path)
        data = sm2_run.file_read(data_path)
        sign = sm2_run.SM2_sign(private_key, public_key, data)[0]
        random_hex_str = sm2_run.SM2_sign(private_key, public_key, data)[1]
        store_path = str(self.ui.sm2_sign_sign_store_file_linetext.text()) + '//' + str(
            self.ui.sm2_sign_sign_filename_linetext.text())
        sm2_run.file_write(store_path, sign)
        self.ui.sm2_log.append(f"签名已经完成！\n随机数为:\n{random_hex_str}")

    def sm2_choose_verify_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm2_verify_file_linetext.setText(FileDirectory[0])

    def choose_verify_sign_store_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm2_verify_sign_store_file_linetext.setText(FileDirectory[0])

    def sm2_verify(self):
        public_key_path = str(self.ui.sm2_pub_file_linetext.text())
        private_key_path = str(self.ui.sm2_pri_file_linetext.text())
        data_path = str(self.ui.sm2_verify_file_linetext.text())
        sign_path = str(self.ui.sm2_verify_sign_store_file_linetext.text())
        if not os.path.exists(public_key_path):
            self.ui.sm2_log.append("公钥文件不存在，请重新输入！")
        if not os.path.exists(private_key_path):
            self.ui.sm2_log.append("私钥文件不存在，请重新输入！")
        if not os.path.exists(data_path):
            self.ui.sm2_log.append("要进行验证的文件不存在，请重新输入！")
        if not os.path.exists(sign_path):
            self.ui.sm2_log.append("签名文件不存在，请重新输入！")
        private_key = sm2_run.file_read(private_key_path)
        public_key = sm2_run.file_read(public_key_path)
        data = sm2_run.file_read(data_path)
        sign = sm2_run.file_read(sign_path)
        try:
            sm2_run.SM2_verify(private_key, public_key, sign, data)
            self.ui.sm2_log.append("验签成功！")
        except:
            self.ui.sm2_log.append("验签失败！")
        finally:
            self.ui.sm2_log.append("验签完成！")

    # sm3
    def sm3_log_clear(self):
        self.ui.sm3_log.clear()

    def choose_hash_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm3_hash_file_linetext.setText(FileDirectory[0])

    def choose_store_hash_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getExistingDirectory(mainwindow, "选择文件")
        self.ui.sm3_store_hash_file_linetext.setText(FileDirectory)

    def hash(self):
        data_path = str(self.ui.sm3_hash_file_linetext.text())
        if not os.path.exists(data_path):
            self.ui.sm3_log.append("文件不存在，请重新输入！")
        write_path = str(self.ui.sm3_store_hash_file_linetext.text()) + '//' + str(
            self.ui.sm3_hash_hash_filename_linetext.text())
        data = sm2_run.file_read(data_path)
        hash_hex = sm3_run.do_hash(data)
        sm2_run.file_write(write_path, hash_hex)
        self.ui.sm3_log.append("散列值计算完成，文件已保存！")

    def sm3_choose_verify_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm3_verify_file_linetext.setText(FileDirectory[0])

    def choose_verify_hash_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm3_verify_hash_file_linetext.setText(FileDirectory[0])

    def sm3_verify(self):
        data_path = str(self.ui.sm3_verify_file_linetext.text())
        hash_path = str(self.ui.sm3_verify_hash_file_linetext.text())
        if not os.path.exists(data_path):
            self.ui.sm3_log.append("要验证的文件不存在，请重新输入！")
        if not os.path.exists(hash_path):
            self.ui.sm3_log.append("哈希文件不存在，请重新输入！")
        data = sm2_run.file_read(data_path)
        hash = sm2_run.file_read(hash_path)
        if sm3_run.verify(data, hash):
            self.ui.sm3_log.append("哈希校验成功！")
        else:
            self.ui.sm3_log.append("哈希校验失败，文件损坏或被篡改！")

    # sm4
    def sm4_log_clear(self):
        self.ui.sm4_log.clear()

    def sm4_choose_enc_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm4_enc_plain_file_linetext.setText(FileDirectory[0])

    def choose_store_cipher_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getExistingDirectory(mainwindow, "选择文件")
        self.ui.sm4_enc_store_cipher_file_linetext.setText(FileDirectory)

    def sm4_enc(self):
        key = str(self.ui.sm4_enc_key_linetext.text())
        key = sm4_run.key_fill(key)
        data_path = str(self.ui.sm4_enc_plain_file_linetext.text())
        store_path = str(self.ui.sm4_enc_store_cipher_file_linetext.text()) + '//' + str(
            self.ui.sm4_cipher_filename_linetext.text())
        if not os.path.exists(data_path):
            self.ui.sm4_log.append("要加密的文件不存在，请重新输入！")
        data = sm2_run.file_read(data_path)
        if len(data) == 0:
            self.ui.sm4_log.append("请确认文件不为空！")
        else:
            start = time.perf_counter()
            cipher_hex = sm4_run.SM4_encrypt_ecb(key, data)
            end = time.perf_counter()
            self.ui.sm4_log.append("加密完成！耗时{:.6}s".format(end - start))
            sm2_run.file_write(store_path, cipher_hex)
            self.ui.sm4_log.append("文件已保存！")

    def sm4_choose_dec_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getOpenFileName(mainwindow, "选择文件")
        self.ui.sm4_dec_cipher_file_linetext.setText(FileDirectory[0])

    def choose_store_plain_file(self):
        mainwindow = QMainWindow()
        FileDialog = QFileDialog(mainwindow)
        FileDirectory = FileDialog.getExistingDirectory(mainwindow, "选择文件")
        self.ui.sm4_dec_store_plain_file_linetext.setText(FileDirectory)

    def sm4_dec(self):
        key = str(self.ui.sm4_dec_key_linetext.text())
        key = sm4_run.key_fill(key)
        data_path = str(self.ui.sm4_dec_cipher_file_linetext.text())
        store_path = str(self.ui.sm4_dec_store_plain_file_linetext.text()) + '//' + str(
            self.ui.sm4_plain_filename_linetext.text())
        if not os.path.exists(data_path):
            self.ui.sm4_log.append("要解密的文件不存在，请重新输入！")
        data = sm2_run.file_read(data_path)

        start = time.perf_counter()
        plaintext = sm4_run.SM4_decrypt_ecb(key, data)
        end = time.perf_counter()
        if data != '' and plaintext == '':
            self.ui.sm4_log.append("解密失败，请检查密钥是否正确！")
        else:
            self.ui.sm4_log.append("解密完成！耗时{:.6}s".format(end - start))
            self.ui.sm4_log.append("文件已保存！")
            sm2_run.file_write(store_path, plaintext)


app = QApplication([])
test = Encrypt()
test.ui.show()
app.exec_()
