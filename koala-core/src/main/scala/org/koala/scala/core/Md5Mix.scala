package org.koala.scala.core

import java.io.{FileInputStream, BufferedInputStream, File}
import java.security.MessageDigest

trait Md5 {

  import Md5Mix.hexDigits

  def byteToHexString(b: Byte): String = {
    var n: Int = b
    if (b < 0) {
      n = n & 0xFF
    }
    val d1 = n / 16
    val d2 = n % 16
    hexDigits(d1) + hexDigits(d2)
  }

  def byteArrayToHexString(b: Array[Byte]): String = {
    val buffer = new StringBuffer()
    for (i <- 0 to (b.length - 1)) {
      buffer.append(byteToHexString(b(i)))
    }
    buffer.toString
  }
}


class FileMd5(val file: File) extends Md5 {


  @Deprecated
  def handle(): String = {
    md5()
  }

  def md5(): String = {
    val bis = new BufferedInputStream(new FileInputStream(file))
    try {
      val md = MessageDigest.getInstance("MD5")
      val buffer = new Array[Byte](256)
      var pos: Int = 0
      while ( {
        pos = bis.read(buffer, 0, 256)
        pos != -1
      }) {
        md.update(buffer, 0, pos)
      }
      byteArrayToHexString(md.digest())
    } catch {
      case ex: Exception => {
        ex.printStackTrace()
        ex.getMessage
      }
    }
    finally {
      if (bis != null)
        bis.close()
    }
  }
}

class StrMd5(val str: String) extends Md5 {

  @Deprecated
  def handle(): String = {
    md5()
  }

  def md5(): String = {
    try {
      val md = MessageDigest.getInstance("MD5")
      val buffer = str.getBytes
      md.update(buffer, 0, str.length)
      byteArrayToHexString(md.digest())
    } catch {
      case ex: Exception => {
        ex.printStackTrace()
        ex.getMessage
      }
    }
  }
}

object Md5Mix {
  val hexDigits = List("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f")

  implicit def fileToMd5(file: File) = new FileMd5(file)

  implicit def strToMd5(str: String) = new StrMd5(str)
}
