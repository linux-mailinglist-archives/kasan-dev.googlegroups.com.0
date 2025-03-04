Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS4OTO7AMGQEX2Y56RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id DCAF1A4D827
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:36 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-390eefb2913sf2573770f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080396; cv=pass;
        d=google.com; s=arc-20240605;
        b=KM5wn0oE5h6krXEN2YBVd3l1lcTPcVLemZyPpOC7RSxYh/kCluPKekuWyyAKDfmvSF
         eMFtopRd/V/KjIlANrOXYK0wZU1taprAyjiu3E5ck2OMVh+ipHw6eZNsKTruhn8CroZu
         A07ZP9xJPcnTCZzCMoCpSCKNWThCWFNGgasmp47G3uWpwazO7L0G+/2E94t/2ZX5Rsuq
         qtnn2MLxgXpcRRnXx4zL/zF8KBwzdjctG0MYw6IBh6ZLbVszt6tYefmPyUl7ABogKjVx
         2X2dAc1RfU7cFl5pZL0dRlttg2AtonFqqdm14t2DGPscT2DvYRhYSuawT1MeeW1/f5BW
         HB1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dfB5r40ZEzq3D4hBInj5z3dyiE5TZf4kc6si+dkZzV0=;
        fh=MUZrcTYGnpc85hPn8lq+vMoHPrBTpbkAAPRkS5gDSl4=;
        b=ayesdxkiXDQob8DSrq+YBfS8tceFO9a01wzz8eMjKb4FkFjaSkpVG4wV2N3lAX0G0J
         QchvqzQYae06W41oIZX1stOtlhaDeeoSdaPiGPK82NDdUQn09UCDbm1Wk54u+cgXl1Cq
         /UiqVNMvCTyToYZC+g0GKK1JyA8zFR26VMvHKLeUAkRkF0JDw6loBk/5ERPrGEZ73whx
         RBrdQLACRwKs122Ip5JV14zdUPxyNgz4T0vXAjBnd5dWsh9GWNdcEItQBDFndeW55mLv
         zNzXcM5EWPf+CmD2cuwo881ASglv6ORk7qR5sP/YRr3J4G/wLIO5OconJ9V5om+5qQxl
         bk2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="GX3ku/uO";
       spf=pass (google.com: domain of 3scfgzwukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ScfGZwUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080396; x=1741685196; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dfB5r40ZEzq3D4hBInj5z3dyiE5TZf4kc6si+dkZzV0=;
        b=umeWbmPCEFCj8kBWVjYpIXys0ftSunZZFfezv9Cfja/qai+EhiGjL52rqmW//J7W6e
         dWMM/+J4Hj572pwf56RDIRKNAcpckLaYxm+2wNTmCpGYM/6d354mLfQEKPACMOIFJ7LI
         vwaJC30+sStFI63lJXOASehzJIKqtEqjVxpfs8wpYe4/qao0XHWtdhUXclB+6h4dFKc2
         Hq8ikHcUQDLg2fgSGH7pOKxnR5iS0o7aaGmUcg7hc7UkIWmHWn0IZosOoTW/cyeG0L+j
         tHqb1qkGifcM2+kiwqHOfW5f5WmPNKtl8fMHDh06u1R+Y/x7Zqnv7JG56wHW8A4SdoEq
         QW4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080396; x=1741685196;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dfB5r40ZEzq3D4hBInj5z3dyiE5TZf4kc6si+dkZzV0=;
        b=t7kuCIMJbbbPu1fdl9dBrNlPxNZi4hbI4/huz3RZ0dj2Y1/W8OpWMSi2lBTokcC9CZ
         G460iLR44I0hxzGeetRuEpVgQ4G6KsFy0UjVscKtJpTcKVkDcLWFF8qT8VfkaqaHeHaU
         4OfaBYIUhUNG0tzhZgeUf3LS0bEpwD4Rm9lUv3YLJwNTyepxBbWOcM7rFDVWO7DB5wOa
         egxY29M/0QYAlWJTU2M9eD5gVEDG/xTceICu9cdAIvcXdgif6L72z6A4n5q/hBS/6JOp
         aIpHPLwBBgBz5NMaOTrpeXA8LC3eliw3E5iPtJRqD41CSSkxwQfQK6O5gvKuH3yeiGiK
         d11Q==
X-Forwarded-Encrypted: i=2; AJvYcCXkxOK/LFYRw0DWRmqvpsE0w42+XyHRDnqfa4BfdVF4FVBaTCm+fLes4vYqy5qkn7JclGgv9A==@lfdr.de
X-Gm-Message-State: AOJu0YwoLEa9iiVEoYV9yUmKMcnJ9Gy3sOXlaiy2Phu6LSEf1B0TdXmu
	Y66Ce5Ppi8o7M0kUqmQRLroYVLdxL/36M8RUrBt/G8RSGZXw7kdh
X-Google-Smtp-Source: AGHT+IHnjCI1MDL8oVOUl8BygJqEl/pwaQQXMdWM3NmeJZG6gL3wmqW4aIi2sAem6A3f9+7SYFW2HA==
X-Received: by 2002:a05:6000:184c:b0:390:f358:85db with SMTP id ffacd0b85a97d-390f358866fmr12755967f8f.30.1741080396028;
        Tue, 04 Mar 2025 01:26:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGVakC84tky34Hfx3HBNP+t/o7pPMSAC14WnHXGGKRUIg==
Received: by 2002:a5d:6d8e:0:b0:38f:2234:229b with SMTP id ffacd0b85a97d-390e12f73f8ls3113693f8f.2.-pod-prod-09-eu;
 Tue, 04 Mar 2025 01:26:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVFrXRkTj2dNBp8c1MFx3ykbetEXRFI8sS/E/pSmunquIm0i43x4D/T2g8CSNR+z7XrIzQ5toOFaHA=@googlegroups.com
X-Received: by 2002:a05:6000:18a6:b0:391:c61:1de8 with SMTP id ffacd0b85a97d-3910c612000mr5672403f8f.16.1741080393547;
        Tue, 04 Mar 2025 01:26:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080393; cv=none;
        d=google.com; s=arc-20240605;
        b=kyrP5LsxfBm+3hReCAYurtIOVw819VeFL1g0hsGQQHHTWemx/GJO4joWrLe5P7D1Gj
         wQHvukmoZZZbvlyhPonRcmswrsERZDdZ2AmZszwim1qoFK47Q0/UmssIU/vUPE0ruGdX
         NvDgN4kzL4BHqVp0CBTEVybei6tdQUACI91tUvflqWe44pWEEcb98PTXx8j8SegEDdwx
         6+bjZAFzdRwmHxl+0HRQpZYJqFHF2R+BQCHjED7KKfLTVrrhR8EqhahVhSvIMF7aH2b2
         CQQOyMsw1KFHB/7Yj2iUeMWUfLQu3Hhq35tsSnLWrUzCJFcUD2AkSjsM3VTLlOXNhXkv
         Wiqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=iDk2VwqwOTTMZfSkXTf6seWDq1RAdZgqLjXPZ94M0QA=;
        fh=dcYpYOdXXSymFPBNhJY0YeTyEQVDCWGnvlGGwN+O+as=;
        b=DwcDC5UeRDOxsYT1HfnZ9jV57UyBtlhcOVA5OFAjfWFy1BFDByFyf/JVzpyRYoL4y3
         8gz/UC0rtfcRPL44IoKx2wWSxUReTPW1zWLqIO4FEchQkPq4ukvYMXqQBsN3VmfRTJ5z
         wLVv8cNnL1mUsXtRzNAoRcVvLv4thHYGjq0TmfwqlZc8AmmwkWhUNjGu+8tuDPjboYXy
         VNR00jQmW6u5pTBazHDShSO+6/Bq3mUg6hnlXXTLBtF7DfrzQhV6ttauPbBN1ysCzbxT
         5X/qNrWB12cG/I7mv0yzEznxfPnoaOTV6LB/DOVFYtYDikYGM1mCiEXpRPaAvMo0u9qZ
         nA7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="GX3ku/uO";
       spf=pass (google.com: domain of 3scfgzwukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ScfGZwUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e482c506si366543f8f.7.2025.03.04.01.26.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3scfgzwukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-ab7f6f6cd96so638328166b.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX4nhAvmMEDnWNYU24Y3L1KvrxCOCdua36hqwM14L/nr/AMgvTQwD0FqIco0EgWTkRU7j74NhnnNkU=@googlegroups.com
X-Received: from ejcsn10.prod.google.com ([2002:a17:906:628a:b0:ac1:fb2a:4a65])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:3e0f:b0:abf:718f:ef27
 with SMTP id a640c23a62f3a-abf718ff14amr868693766b.1.1741080393090; Tue, 04
 Mar 2025 01:26:33 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:30 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-32-elver@google.com>
Subject: [PATCH v2 31/34] drivers/tty: Enable capability analysis for core files
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="GX3ku/uO";       spf=pass
 (google.com: domain of 3scfgzwukctgyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ScfGZwUKCTgYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Enable capability analysis for drivers/tty/*.

This demonstrates a larger conversion to use Clang's capability
analysis. The benefit is additional static checking of locking rules,
along with better documentation.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Jiri Slaby <jirislaby@kernel.org>
---
v2:
* New patch.
---
 drivers/tty/Makefile      |  3 +++
 drivers/tty/n_tty.c       | 16 ++++++++++++++++
 drivers/tty/pty.c         |  1 +
 drivers/tty/sysrq.c       |  1 +
 drivers/tty/tty.h         |  8 ++++----
 drivers/tty/tty_buffer.c  |  8 +++-----
 drivers/tty/tty_io.c      | 12 +++++++++---
 drivers/tty/tty_ioctl.c   |  2 +-
 drivers/tty/tty_ldisc.c   | 35 ++++++++++++++++++++++++++++++++---
 drivers/tty/tty_ldsem.c   |  2 ++
 drivers/tty/tty_mutex.c   |  4 ++++
 drivers/tty/tty_port.c    |  2 ++
 include/linux/tty.h       | 14 +++++++-------
 include/linux/tty_flip.h  |  4 ++--
 include/linux/tty_ldisc.h | 19 ++++++++++---------
 15 files changed, 97 insertions(+), 34 deletions(-)

diff --git a/drivers/tty/Makefile b/drivers/tty/Makefile
index 07aca5184a55..35e1a62cbe16 100644
--- a/drivers/tty/Makefile
+++ b/drivers/tty/Makefile
@@ -1,4 +1,7 @@
 # SPDX-License-Identifier: GPL-2.0
+
+CAPABILITY_ANALYSIS := y
+
 obj-$(CONFIG_TTY)		+= tty_io.o n_tty.o tty_ioctl.o tty_ldisc.o \
 				   tty_buffer.o tty_port.o tty_mutex.o \
 				   tty_ldsem.o tty_baudrate.o tty_jobctrl.o \
diff --git a/drivers/tty/n_tty.c b/drivers/tty/n_tty.c
index 5e9ca4376d68..45925fc5a8fd 100644
--- a/drivers/tty/n_tty.c
+++ b/drivers/tty/n_tty.c
@@ -1088,6 +1088,7 @@ static void __isig(int sig, struct tty_struct *tty)
  * Locking: %ctrl.lock
  */
 static void isig(int sig, struct tty_struct *tty)
+	__must_hold_shared(&tty->termios_rwsem)
 {
 	struct n_tty_data *ldata = tty->disc_data;
 
@@ -1135,6 +1136,7 @@ static void isig(int sig, struct tty_struct *tty)
  * Note: may get exclusive %termios_rwsem if flushing input buffer
  */
 static void n_tty_receive_break(struct tty_struct *tty)
+	__must_hold_shared(&tty->termios_rwsem)
 {
 	struct n_tty_data *ldata = tty->disc_data;
 
@@ -1204,6 +1206,7 @@ static void n_tty_receive_parity_error(const struct tty_struct *tty,
 
 static void
 n_tty_receive_signal_char(struct tty_struct *tty, int signal, u8 c)
+	__must_hold_shared(&tty->termios_rwsem)
 {
 	isig(signal, tty);
 	if (I_IXON(tty))
@@ -1353,6 +1356,7 @@ static bool n_tty_receive_char_canon(struct tty_struct *tty, u8 c)
 
 static void n_tty_receive_char_special(struct tty_struct *tty, u8 c,
 				       bool lookahead_done)
+	__must_hold_shared(&tty->termios_rwsem)
 {
 	struct n_tty_data *ldata = tty->disc_data;
 
@@ -1463,6 +1467,7 @@ static void n_tty_receive_char_closing(struct tty_struct *tty, u8 c,
 
 static void
 n_tty_receive_char_flagged(struct tty_struct *tty, u8 c, u8 flag)
+	__must_hold_shared(&tty->termios_rwsem)
 {
 	switch (flag) {
 	case TTY_BREAK:
@@ -1483,6 +1488,7 @@ n_tty_receive_char_flagged(struct tty_struct *tty, u8 c, u8 flag)
 
 static void
 n_tty_receive_char_lnext(struct tty_struct *tty, u8 c, u8 flag)
+	__must_hold_shared(&tty->termios_rwsem)
 {
 	struct n_tty_data *ldata = tty->disc_data;
 
@@ -1540,6 +1546,7 @@ n_tty_receive_buf_real_raw(const struct tty_struct *tty, const u8 *cp,
 static void
 n_tty_receive_buf_raw(struct tty_struct *tty, const u8 *cp, const u8 *fp,
 		      size_t count)
+	__must_hold_shared(&tty->termios_rwsem)
 {
 	struct n_tty_data *ldata = tty->disc_data;
 	u8 flag = TTY_NORMAL;
@@ -1571,6 +1578,7 @@ n_tty_receive_buf_closing(struct tty_struct *tty, const u8 *cp, const u8 *fp,
 static void n_tty_receive_buf_standard(struct tty_struct *tty, const u8 *cp,
 				       const u8 *fp, size_t count,
 				       bool lookahead_done)
+	__must_hold_shared(&tty->termios_rwsem)
 {
 	struct n_tty_data *ldata = tty->disc_data;
 	u8 flag = TTY_NORMAL;
@@ -1609,6 +1617,7 @@ static void n_tty_receive_buf_standard(struct tty_struct *tty, const u8 *cp,
 
 static void __receive_buf(struct tty_struct *tty, const u8 *cp, const u8 *fp,
 			  size_t count)
+	__must_hold_shared(&tty->termios_rwsem)
 {
 	struct n_tty_data *ldata = tty->disc_data;
 	bool preops = I_ISTRIP(tty) || (I_IUCLC(tty) && L_IEXTEN(tty));
@@ -2188,6 +2197,10 @@ static ssize_t n_tty_read(struct tty_struct *tty, struct file *file, u8 *kbuf,
 				return kb - kbuf;
 		}
 
+		/* Adopted locks from prior call. */
+		__acquire(&ldata->atomic_read_lock);
+		__acquire_shared(&tty->termios_rwsem);
+
 		/* No more data - release locks and stop retries */
 		n_tty_kick_worker(tty);
 		n_tty_check_unthrottle(tty);
@@ -2305,6 +2318,9 @@ static ssize_t n_tty_read(struct tty_struct *tty, struct file *file, u8 *kbuf,
 more_to_be_read:
 				remove_wait_queue(&tty->read_wait, &wait);
 				*cookie = cookie;
+				/* Hand-off locks to retry with cookie set. */
+				__release_shared(&tty->termios_rwsem);
+				__release(&ldata->atomic_read_lock);
 				return kb - kbuf;
 			}
 		}
diff --git a/drivers/tty/pty.c b/drivers/tty/pty.c
index 8bb1a01fef2a..8d4eb0f4c84c 100644
--- a/drivers/tty/pty.c
+++ b/drivers/tty/pty.c
@@ -824,6 +824,7 @@ static int ptmx_open(struct inode *inode, struct file *filp)
 	tty = tty_init_dev(ptm_driver, index);
 	/* The tty returned here is locked so we can safely
 	   drop the mutex */
+	lockdep_assert_held(&tty->legacy_mutex);
 	mutex_unlock(&tty_mutex);
 
 	retval = PTR_ERR(tty);
diff --git a/drivers/tty/sysrq.c b/drivers/tty/sysrq.c
index f85ce02e4725..82dfa964c965 100644
--- a/drivers/tty/sysrq.c
+++ b/drivers/tty/sysrq.c
@@ -149,6 +149,7 @@ static const struct sysrq_key_op sysrq_unraw_op = {
 static void sysrq_handle_crash(u8 key)
 {
 	/* release the RCU read lock before crashing */
+	lockdep_assert_in_rcu_read_lock();
 	rcu_read_unlock();
 
 	panic("sysrq triggered crash\n");
diff --git a/drivers/tty/tty.h b/drivers/tty/tty.h
index 93cf5ef1e857..1a3c2f663b28 100644
--- a/drivers/tty/tty.h
+++ b/drivers/tty/tty.h
@@ -60,15 +60,15 @@ static inline void tty_set_flow_change(struct tty_struct *tty,
 	smp_mb();
 }
 
-int tty_ldisc_lock(struct tty_struct *tty, unsigned long timeout);
-void tty_ldisc_unlock(struct tty_struct *tty);
+int tty_ldisc_lock(struct tty_struct *tty, unsigned long timeout) __cond_acquires(0, &tty->ldisc_sem);
+void tty_ldisc_unlock(struct tty_struct *tty) __releases(&tty->ldisc_sem);
 
 int __tty_check_change(struct tty_struct *tty, int sig);
 int tty_check_change(struct tty_struct *tty);
 void __stop_tty(struct tty_struct *tty);
 void __start_tty(struct tty_struct *tty);
-void tty_write_unlock(struct tty_struct *tty);
-int tty_write_lock(struct tty_struct *tty, bool ndelay);
+void tty_write_unlock(struct tty_struct *tty) __releases(&tty->atomic_write_lock);
+int tty_write_lock(struct tty_struct *tty, bool ndelay) __cond_acquires(0, &tty->atomic_write_lock);
 void tty_vhangup_session(struct tty_struct *tty);
 void tty_open_proc_set_tty(struct file *filp, struct tty_struct *tty);
 int tty_signal_session_leader(struct tty_struct *tty, int exit_session);
diff --git a/drivers/tty/tty_buffer.c b/drivers/tty/tty_buffer.c
index 79f0ff94ce00..dcc56537290f 100644
--- a/drivers/tty/tty_buffer.c
+++ b/drivers/tty/tty_buffer.c
@@ -52,10 +52,8 @@
  */
 void tty_buffer_lock_exclusive(struct tty_port *port)
 {
-	struct tty_bufhead *buf = &port->buf;
-
-	atomic_inc(&buf->priority);
-	mutex_lock(&buf->lock);
+	atomic_inc(&port->buf.priority);
+	mutex_lock(&port->buf.lock);
 }
 EXPORT_SYMBOL_GPL(tty_buffer_lock_exclusive);
 
@@ -73,7 +71,7 @@ void tty_buffer_unlock_exclusive(struct tty_port *port)
 	bool restart = buf->head->commit != buf->head->read;
 
 	atomic_dec(&buf->priority);
-	mutex_unlock(&buf->lock);
+	mutex_unlock(&port->buf.lock);
 
 	if (restart)
 		queue_work(system_unbound_wq, &buf->work);
diff --git a/drivers/tty/tty_io.c b/drivers/tty/tty_io.c
index 449dbd216460..1eb3794fde4b 100644
--- a/drivers/tty/tty_io.c
+++ b/drivers/tty/tty_io.c
@@ -167,6 +167,7 @@ static void release_tty(struct tty_struct *tty, int idx);
  * Locking: none. Must be called after tty is definitely unused
  */
 static void free_tty_struct(struct tty_struct *tty)
+	__capability_unsafe(/* destructor */)
 {
 	tty_ldisc_deinit(tty);
 	put_device(tty->dev);
@@ -965,7 +966,7 @@ static ssize_t iterate_tty_write(struct tty_ldisc *ld, struct tty_struct *tty,
 	ssize_t ret, written = 0;
 
 	ret = tty_write_lock(tty, file->f_flags & O_NDELAY);
-	if (ret < 0)
+	if (ret)
 		return ret;
 
 	/*
@@ -1154,7 +1155,7 @@ int tty_send_xchar(struct tty_struct *tty, u8 ch)
 		return 0;
 	}
 
-	if (tty_write_lock(tty, false) < 0)
+	if (tty_write_lock(tty, false))
 		return -ERESTARTSYS;
 
 	down_read(&tty->termios_rwsem);
@@ -1391,6 +1392,7 @@ static int tty_reopen(struct tty_struct *tty)
  * Return: new tty structure
  */
 struct tty_struct *tty_init_dev(struct tty_driver *driver, int idx)
+	__capability_unsafe(/* returns with locked tty */)
 {
 	struct tty_struct *tty;
 	int retval;
@@ -1874,6 +1876,7 @@ int tty_release(struct inode *inode, struct file *filp)
  * will not work then. It expects inodes to be from devpts FS.
  */
 static struct tty_struct *tty_open_current_tty(dev_t device, struct file *filp)
+	__capability_unsafe(/* returns with locked tty */)
 {
 	struct tty_struct *tty;
 	int retval;
@@ -2037,6 +2040,7 @@ EXPORT_SYMBOL_GPL(tty_kopen_shared);
  */
 static struct tty_struct *tty_open_by_driver(dev_t device,
 					     struct file *filp)
+	__capability_unsafe(/* returns with locked tty */)
 {
 	struct tty_struct *tty;
 	struct tty_driver *driver = NULL;
@@ -2137,6 +2141,8 @@ static int tty_open(struct inode *inode, struct file *filp)
 		goto retry_open;
 	}
 
+	lockdep_assert_held(&tty->legacy_mutex);
+
 	tty_add_file(tty, filp);
 
 	check_tty_count(tty, __func__);
@@ -2486,7 +2492,7 @@ static int send_break(struct tty_struct *tty, unsigned int duration)
 		return tty->ops->break_ctl(tty, duration);
 
 	/* Do the work ourselves */
-	if (tty_write_lock(tty, false) < 0)
+	if (tty_write_lock(tty, false))
 		return -EINTR;
 
 	retval = tty->ops->break_ctl(tty, -1);
diff --git a/drivers/tty/tty_ioctl.c b/drivers/tty/tty_ioctl.c
index 85de90eebc7b..a7ae6cbf3450 100644
--- a/drivers/tty/tty_ioctl.c
+++ b/drivers/tty/tty_ioctl.c
@@ -489,7 +489,7 @@ static int set_termios(struct tty_struct *tty, void __user *arg, int opt)
 		if (retval < 0)
 			return retval;
 
-		if (tty_write_lock(tty, false) < 0)
+		if (tty_write_lock(tty, false))
 			goto retry_write_wait;
 
 		/* Racing writer? */
diff --git a/drivers/tty/tty_ldisc.c b/drivers/tty/tty_ldisc.c
index d80e9d4c974b..e07a5980604e 100644
--- a/drivers/tty/tty_ldisc.c
+++ b/drivers/tty/tty_ldisc.c
@@ -237,6 +237,7 @@ const struct seq_operations tty_ldiscs_seq_ops = {
  * to wait for any ldisc lifetime events to finish.
  */
 struct tty_ldisc *tty_ldisc_ref_wait(struct tty_struct *tty)
+	__cond_acquires_shared(nonnull, &tty->ldisc_sem)
 {
 	struct tty_ldisc *ld;
 
@@ -257,6 +258,7 @@ EXPORT_SYMBOL_GPL(tty_ldisc_ref_wait);
  * and timer functions.
  */
 struct tty_ldisc *tty_ldisc_ref(struct tty_struct *tty)
+	__cond_acquires_shared(nonnull, &tty->ldisc_sem)
 {
 	struct tty_ldisc *ld = NULL;
 
@@ -277,26 +279,43 @@ EXPORT_SYMBOL_GPL(tty_ldisc_ref);
  * in IRQ context.
  */
 void tty_ldisc_deref(struct tty_ldisc *ld)
+	__releases_shared(&ld->tty->ldisc_sem)
 {
 	ldsem_up_read(&ld->tty->ldisc_sem);
 }
 EXPORT_SYMBOL_GPL(tty_ldisc_deref);
 
+/*
+ * Note: Capability analysis does not like asymmetric interfaces (above types
+ * for ref and deref are tty_struct and tty_ldisc respectively -- which are
+ * dependent, but the compiler cannot figure that out); in this case, work
+ * around that with this helper which takes an unused @tty argument but tells
+ * the analysis which lock is released.
+ */
+static inline void __tty_ldisc_deref(struct tty_struct *tty, struct tty_ldisc *ld)
+	__releases_shared(&tty->ldisc_sem)
+	__capability_unsafe(/* matches released with tty_ldisc_ref() */)
+{
+	tty_ldisc_deref(ld);
+}
 
 static inline int
 __tty_ldisc_lock(struct tty_struct *tty, unsigned long timeout)
+	__cond_acquires(true, &tty->ldisc_sem)
 {
 	return ldsem_down_write(&tty->ldisc_sem, timeout);
 }
 
 static inline int
 __tty_ldisc_lock_nested(struct tty_struct *tty, unsigned long timeout)
+	__cond_acquires(true, &tty->ldisc_sem)
 {
 	return ldsem_down_write_nested(&tty->ldisc_sem,
 				       LDISC_SEM_OTHER, timeout);
 }
 
 static inline void __tty_ldisc_unlock(struct tty_struct *tty)
+	__releases(&tty->ldisc_sem)
 {
 	ldsem_up_write(&tty->ldisc_sem);
 }
@@ -328,6 +347,8 @@ void tty_ldisc_unlock(struct tty_struct *tty)
 static int
 tty_ldisc_lock_pair_timeout(struct tty_struct *tty, struct tty_struct *tty2,
 			    unsigned long timeout)
+	__cond_acquires(0, &tty->ldisc_sem)
+	__cond_acquires(0, &tty2->ldisc_sem)
 {
 	int ret;
 
@@ -362,16 +383,23 @@ tty_ldisc_lock_pair_timeout(struct tty_struct *tty, struct tty_struct *tty2,
 }
 
 static void tty_ldisc_lock_pair(struct tty_struct *tty, struct tty_struct *tty2)
+	__acquires(&tty->ldisc_sem)
+	__acquires(&tty2->ldisc_sem)
+	__capability_unsafe(/* MAX_SCHEDULE_TIMEOUT ensures acquisition */)
 {
 	tty_ldisc_lock_pair_timeout(tty, tty2, MAX_SCHEDULE_TIMEOUT);
 }
 
 static void tty_ldisc_unlock_pair(struct tty_struct *tty,
 				  struct tty_struct *tty2)
+	__releases(&tty->ldisc_sem)
+	__releases(&tty2->ldisc_sem)
 {
 	__tty_ldisc_unlock(tty);
 	if (tty2)
 		__tty_ldisc_unlock(tty2);
+	else
+		__release(&tty2->ldisc_sem);
 }
 
 /**
@@ -387,7 +415,7 @@ void tty_ldisc_flush(struct tty_struct *tty)
 
 	tty_buffer_flush(tty, ld);
 	if (ld)
-		tty_ldisc_deref(ld);
+		__tty_ldisc_deref(tty, ld);
 }
 EXPORT_SYMBOL_GPL(tty_ldisc_flush);
 
@@ -694,7 +722,7 @@ void tty_ldisc_hangup(struct tty_struct *tty, bool reinit)
 	tty_ldisc_debug(tty, "%p: hangup\n", tty->ldisc);
 
 	ld = tty_ldisc_ref(tty);
-	if (ld != NULL) {
+	if (ld) {
 		if (ld->ops->flush_buffer)
 			ld->ops->flush_buffer(tty);
 		tty_driver_flush_buffer(tty);
@@ -703,7 +731,7 @@ void tty_ldisc_hangup(struct tty_struct *tty, bool reinit)
 			ld->ops->write_wakeup(tty);
 		if (ld->ops->hangup)
 			ld->ops->hangup(tty);
-		tty_ldisc_deref(ld);
+		__tty_ldisc_deref(tty, ld);
 	}
 
 	wake_up_interruptible_poll(&tty->write_wait, EPOLLOUT);
@@ -716,6 +744,7 @@ void tty_ldisc_hangup(struct tty_struct *tty, bool reinit)
 	 * Avoid racing set_ldisc or tty_ldisc_release
 	 */
 	tty_ldisc_lock(tty, MAX_SCHEDULE_TIMEOUT);
+	lockdep_assert_held_write(&tty->ldisc_sem);
 
 	if (tty->driver->flags & TTY_DRIVER_RESET_TERMIOS)
 		tty_reset_termios(tty);
diff --git a/drivers/tty/tty_ldsem.c b/drivers/tty/tty_ldsem.c
index 3be428c16260..26d924bb5a46 100644
--- a/drivers/tty/tty_ldsem.c
+++ b/drivers/tty/tty_ldsem.c
@@ -390,6 +390,7 @@ void ldsem_up_read(struct ld_semaphore *sem)
 {
 	long count;
 
+	__release_shared(sem);
 	rwsem_release(&sem->dep_map, _RET_IP_);
 
 	count = atomic_long_add_return(-LDSEM_READ_BIAS, &sem->count);
@@ -404,6 +405,7 @@ void ldsem_up_write(struct ld_semaphore *sem)
 {
 	long count;
 
+	__release(sem);
 	rwsem_release(&sem->dep_map, _RET_IP_);
 
 	count = atomic_long_add_return(-LDSEM_WRITE_BIAS, &sem->count);
diff --git a/drivers/tty/tty_mutex.c b/drivers/tty/tty_mutex.c
index 784e46a0a3b1..e5576fd6f5a4 100644
--- a/drivers/tty/tty_mutex.c
+++ b/drivers/tty/tty_mutex.c
@@ -41,12 +41,16 @@ void tty_lock_slave(struct tty_struct *tty)
 {
 	if (tty && tty != tty->link)
 		tty_lock(tty);
+	else
+		__acquire(&tty->legacy_mutex);
 }
 
 void tty_unlock_slave(struct tty_struct *tty)
 {
 	if (tty && tty != tty->link)
 		tty_unlock(tty);
+	else
+		__release(&tty->legacy_mutex);
 }
 
 void tty_set_lock_subclass(struct tty_struct *tty)
diff --git a/drivers/tty/tty_port.c b/drivers/tty/tty_port.c
index 14cca33d2269..bcb65a26a6bf 100644
--- a/drivers/tty/tty_port.c
+++ b/drivers/tty/tty_port.c
@@ -509,6 +509,7 @@ EXPORT_SYMBOL(tty_port_lower_dtr_rts);
  */
 int tty_port_block_til_ready(struct tty_port *port,
 				struct tty_struct *tty, struct file *filp)
+	__must_hold(&tty->legacy_mutex)
 {
 	int do_clocal = 0, retval;
 	unsigned long flags;
@@ -764,6 +765,7 @@ EXPORT_SYMBOL_GPL(tty_port_install);
  */
 int tty_port_open(struct tty_port *port, struct tty_struct *tty,
 							struct file *filp)
+	__must_hold(&tty->legacy_mutex)
 {
 	spin_lock_irq(&port->lock);
 	++port->count;
diff --git a/include/linux/tty.h b/include/linux/tty.h
index 2372f9357240..ee1ba62fc398 100644
--- a/include/linux/tty.h
+++ b/include/linux/tty.h
@@ -234,8 +234,8 @@ struct tty_struct {
 	void *disc_data;
 	void *driver_data;
 	spinlock_t files_lock;
-	int write_cnt;
-	u8 *write_buf;
+	int write_cnt __guarded_by(&atomic_write_lock);
+	u8 *write_buf __guarded_by(&atomic_write_lock);
 
 	struct list_head tty_files;
 
@@ -500,11 +500,11 @@ long vt_compat_ioctl(struct tty_struct *tty, unsigned int cmd,
 
 /* tty_mutex.c */
 /* functions for preparation of BKL removal */
-void tty_lock(struct tty_struct *tty);
-int  tty_lock_interruptible(struct tty_struct *tty);
-void tty_unlock(struct tty_struct *tty);
-void tty_lock_slave(struct tty_struct *tty);
-void tty_unlock_slave(struct tty_struct *tty);
+void tty_lock(struct tty_struct *tty) __acquires(&tty->legacy_mutex);
+int  tty_lock_interruptible(struct tty_struct *tty) __cond_acquires(0, &tty->legacy_mutex);
+void tty_unlock(struct tty_struct *tty) __releases(&tty->legacy_mutex);
+void tty_lock_slave(struct tty_struct *tty) __acquires(&tty->legacy_mutex);
+void tty_unlock_slave(struct tty_struct *tty) __releases(&tty->legacy_mutex);
 void tty_set_lock_subclass(struct tty_struct *tty);
 
 #endif
diff --git a/include/linux/tty_flip.h b/include/linux/tty_flip.h
index af4fce98f64e..2214714059f8 100644
--- a/include/linux/tty_flip.h
+++ b/include/linux/tty_flip.h
@@ -86,7 +86,7 @@ static inline size_t tty_insert_flip_string(struct tty_port *port,
 size_t tty_ldisc_receive_buf(struct tty_ldisc *ld, const u8 *p, const u8 *f,
 			     size_t count);
 
-void tty_buffer_lock_exclusive(struct tty_port *port);
-void tty_buffer_unlock_exclusive(struct tty_port *port);
+void tty_buffer_lock_exclusive(struct tty_port *port) __acquires(&port->buf.lock);
+void tty_buffer_unlock_exclusive(struct tty_port *port) __releases(&port->buf.lock);
 
 #endif /* _LINUX_TTY_FLIP_H */
diff --git a/include/linux/tty_ldisc.h b/include/linux/tty_ldisc.h
index af01e89074b2..d834cf115d52 100644
--- a/include/linux/tty_ldisc.h
+++ b/include/linux/tty_ldisc.h
@@ -14,7 +14,7 @@ struct tty_struct;
 /*
  * the semaphore definition
  */
-struct ld_semaphore {
+struct_with_capability(ld_semaphore) {
 	atomic_long_t		count;
 	raw_spinlock_t		wait_lock;
 	unsigned int		wait_readers;
@@ -33,21 +33,22 @@ do {								\
 	static struct lock_class_key __key;			\
 								\
 	__init_ldsem((sem), #sem, &__key);			\
+	__assert_cap(sem);					\
 } while (0)
 
 
-int ldsem_down_read(struct ld_semaphore *sem, long timeout);
-int ldsem_down_read_trylock(struct ld_semaphore *sem);
-int ldsem_down_write(struct ld_semaphore *sem, long timeout);
-int ldsem_down_write_trylock(struct ld_semaphore *sem);
-void ldsem_up_read(struct ld_semaphore *sem);
-void ldsem_up_write(struct ld_semaphore *sem);
+int ldsem_down_read(struct ld_semaphore *sem, long timeout) __cond_acquires_shared(true, sem);
+int ldsem_down_read_trylock(struct ld_semaphore *sem) __cond_acquires_shared(true, sem);
+int ldsem_down_write(struct ld_semaphore *sem, long timeout) __cond_acquires(true, sem);
+int ldsem_down_write_trylock(struct ld_semaphore *sem) __cond_acquires(true, sem);
+void ldsem_up_read(struct ld_semaphore *sem) __releases_shared(sem);
+void ldsem_up_write(struct ld_semaphore *sem) __releases(sem);
 
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
 int ldsem_down_read_nested(struct ld_semaphore *sem, int subclass,
-		long timeout);
+		long timeout) __cond_acquires_shared(true, sem);
 int ldsem_down_write_nested(struct ld_semaphore *sem, int subclass,
-		long timeout);
+		long timeout) __cond_acquires(true, sem);
 #else
 # define ldsem_down_read_nested(sem, subclass, timeout)		\
 		ldsem_down_read(sem, timeout)
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-32-elver%40google.com.
