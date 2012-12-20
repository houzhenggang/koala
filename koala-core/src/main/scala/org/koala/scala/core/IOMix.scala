package org.koala.scala.core

import io.Source
import java.io.{FileWriter, BufferedWriter, File, PrintWriter}
import org.apache.commons.io.FileUtils

/**
 * 扩展文件(File)对象操作方法；
 * <pre>
 * import org.koala.scala.core.IOMix._</br>
 * val f=new File("/tmp/demo.txt")</br>
 * println(f.text)</br>
 * </pre>
 * @version 1.0
 * @author ya_feng_li@163.com
 */
class IOMix(file: File) {
  /**
   * <p>读取文件内容作为字符串。</p>
   * @return 返回字符串文件内容。
   */
  def text: String = {
    if (!file.exists()) file.createNewFile()
    val bufferSource = Source.fromFile(file)
    try {
      bufferSource.mkString
    }
    finally {
      bufferSource.close()
    }
  }

  /**
   * <p>将内容写入文件内。</p>
   * @param content 需要写入文件的内容。
   */
  def text(content: String) {
    withPrintWriter {
      writer =>
        writer.print(content)
    }
  }

  /**
   * <p>使用以文件本身构建的PrintWriter。</p>
   * @param op 以PrintWriter为参数的调用函数。
   */
  def withPrintWriter(op: PrintWriter => Unit) {
    if (!file.getParentFile.exists()) FileUtils.forceMkdir(file.getParentFile)
    val p = new PrintWriter(file)
    try {
      op(p)
    } finally {
      p.close()
    }
  }

  /**
   * <p>使用以文件本身构建的BufferedWriter。</p>
   * @param op 以BufferedWriter为参数的调用函数。
   * @see #withBufferedWriter(op: BufferedWriter => Unit)
   */
  def withBufferedWriter(op: BufferedWriter => Unit) {
    if (!file.getParentFile.exists()) FileUtils.forceMkdir(file.getParentFile)
    val p = new BufferedWriter(new FileWriter(file))
    try {
      op(p)
    } finally {
      p.close()
    }
  }

  /**
   * <p>遍历文件中每一行内容。</p>
   * @param call 处理字符串的函数。
   */
  def eachLine(call: (String) => Unit) {
    val bufferSource = Source.fromFile(file)
    try {
      bufferSource.getLines().foreach {
        line =>
          call(line)
      }
    }
    finally {
      bufferSource.close()
    }
  }

  /**
   * <p>复制文件到目标目录。</p>
   * @param destDir 目标文件目录
   */
  def copyTo(destDir: File) {
    if (destDir.isDirectory && !destDir.exists()) {
      FileUtils.forceMkdir(destDir)
    }
    FileUtils.copyFileToDirectory(file, destDir)
  }

  /**
   * <p>移动文件到目标目录。</p>
   * @param destDir 目标文件目录
   */
  def moveTo(destDir: File) {
    if (destDir.isDirectory && !destDir.exists()) {
      FileUtils.forceMkdir(destDir)
    }
    FileUtils.moveToDirectory(file, destDir, true)
  }

  /**
   * <p>将文件重命名为目标文件。</p>
   * @param destFile 目标文件
   */
  def rename(destFile: File) {
    val destDir = destFile.getParentFile
    if (destDir.isDirectory && !destDir.exists()) {
      FileUtils.forceMkdir(destDir)
    }
    FileUtils.moveFile(file, destFile)
  }
}

object IOMix {
  implicit def io(file: File) = new IOMix(file)
}

