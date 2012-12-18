package org.koala.scala.core

import io.Source
import java.io.{FileWriter, BufferedWriter, File, PrintWriter}
import org.apache.commons.io.FileUtils

/**
 * 隐式转换扩展File操作；
 * @param file
 */
class IOMix(file: File) {
  /**
   * @return
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

  def text(content: String) {
    withPrintWriter {
      writer =>
        writer.print(content)
    }
  }

  def withPrintWriter(op: PrintWriter => Unit) {
    if (!file.getParentFile.exists()) FileUtils.forceMkdir(file.getParentFile)
    val p = new PrintWriter(file)
    try {
      op(p)
    } finally {
      p.close()
    }
  }

  def withBufferedWriter(op: BufferedWriter => Unit) {
    if (!file.getParentFile.exists()) FileUtils.forceMkdir(file.getParentFile)
    val p = new BufferedWriter(new FileWriter(file))
    try {
      op(p)
    } finally {
      p.close()
    }
  }

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

  def copyTo(destDir: File) {
    if (destDir.isDirectory && !destDir.exists()) {
      FileUtils.forceMkdir(destDir)
    }
    FileUtils.copyFileToDirectory(file, destDir)
  }

  def moveTo(destFile: File) {
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

