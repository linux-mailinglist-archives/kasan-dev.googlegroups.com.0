Return-Path: <kasan-dev+bncBCALX3WVYQORBPUTWKCAMGQEGQ45BBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id EBD453703BD
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 00:50:39 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id c3-20020a0568081383b029010231e3ec8csf29401402oiw.22
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 15:50:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619823038; cv=pass;
        d=google.com; s=arc-20160816;
        b=My/g2pvn7StXxQj/10xAG7tuTpOlQVKD/4uiahfVuT2FmrBszbmqMHAAJxyi+ELVdA
         GLIvCEvqeR0iget9dhuI2GXUq9TnHOGWp3XmkCrnUs/GCajpdbefNElLpOQSdillHTEf
         MXs4dUim2b2N4pmLOkYQ1bs3meZkMG7NNC8Nfs80U7tk1X/znjwtCPAvcKcEhqLJeUFj
         m+t+N7ucikQeXx/iq3uogJDpTvOY+Mb9QFVO41jBiAUlm7jzCc1to1Tsb2VQXKIkP6Mz
         IyiefBEAk7u83FzD0aTVDY3zM/0/7cj4gGlIwaaJxupQvfH4O7vYkmCJfrPh1eztKx4m
         7VZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=i7yQB8QefJBRyVwIvvCLQQvD6423yKhv4b9zB3f2mZk=;
        b=NVKGp2ctYDHxSarXjZnE4Sk+yj3XVsLbDxLs4oS1IC03npI0B7pm6lgdf2cH3hKIPT
         ad6WlKbbm0cOuIbXvFJIOqEcmNfFd0Ad8CdSvWHGdCZnakS9mtyNaUCqU9tf/sEFYri6
         WSEW97nZ/Gzoln1F4K1vD8mN+A5zgwRTZ6DWj5exv3SMWpCJ0keNY2UuzY2lYvcTpr4R
         eUcN0JFdSPidK3Pxb3HCPSJLDXNZaclk3xSH4x33myivfs+1lsEWI3PQ8kuo2IVyaHgt
         7Ka47khT+lhLicshhxh/gU7HZpzvS6IWeoN39D5idLocohTh6LH+gd1avZWe7WNJE6rG
         Lg2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=i7yQB8QefJBRyVwIvvCLQQvD6423yKhv4b9zB3f2mZk=;
        b=KTL/l+5YzZTs0WR1lZlWuNntoYdZftY44Y2/nM8fyYV7MqrU6NJYFamRl3CIo+YBjR
         D5m/DM+ISL1EE/18aBYLphZrkKzhVXj0/KQjozEnQx9DchCzo4OwW1EP/CfWfMyS8OLi
         MwN/Dhou+UeAZXoWB7gqOXnLy3L69Hz37BAdxbYxdefi7MDYEbSGHkyb4cg5kQvQZ2Fz
         iYSZ1RoHLSg+IzjiBvZ0ek+LhU233ZRv4gQRsd70XWFDsNb46OjKrl/L51bUIT40v8xa
         9cyCDf6X+NK58vzl3eQkQWQQqv4iL0VivGHIZ4NIS505SoVRyIIe8Bvj6kwDIpUdsI4B
         FzDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i7yQB8QefJBRyVwIvvCLQQvD6423yKhv4b9zB3f2mZk=;
        b=mkLSu/AhG73+07qAG0tIeIdswIFQANZPGajvlp2ztn40MtDo3XU1+fZtwVNtwUrice
         4vO4iqNS2F7FnvUU9COzuEx/jp7lVcSsFHEBFh733PfkdWMHXwMKYUgdmJzRiSoAPnHP
         NiNW3vKdXpm01CRFOqnN52/RRvWvO+vVaMKTnj8L2jJVxhAq2QJnJuo22FcC09OxObQs
         7ttwIcWo9meqDGGxuaa5QskGY/DgJQtiIbvQu8uIMAG/ojHXeE0oizjS5gmCyKmBgV/x
         jbdi6xsjeZejdO00cr+SPlIV6ECMbWDP2qsY1Q46vLQCjiVoNDkZ2YGk7T/Ajl60lDs/
         e/1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/CdJtrR955FKeqWp9uDcd8D+q1ikaXBJQyLoG/72kjkmagi+6
	IUw2DlPAmcLrWPlXI8zmFnU=
X-Google-Smtp-Source: ABdhPJwjAumX4ollzECVznWhqAXsjqwFLZzJWXWnjEFHzFJ3wdoOAqPkKM72Mmj/pA4k8pzKvJYMMQ==
X-Received: by 2002:a9d:6a05:: with SMTP id g5mr5436173otn.232.1619823038596;
        Fri, 30 Apr 2021 15:50:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:fc51:: with SMTP id a78ls2234533oii.9.gmail; Fri, 30 Apr
 2021 15:50:38 -0700 (PDT)
X-Received: by 2002:aca:5856:: with SMTP id m83mr5617952oib.105.1619823038243;
        Fri, 30 Apr 2021 15:50:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619823038; cv=none;
        d=google.com; s=arc-20160816;
        b=R5YAMve6RrWelDsKjaGKqhVB4VjgCV1rkz5vAc7dPdi8DnRgLwEuwV4VMzt3RFO3b7
         hZo+FOjHRrWoZe3fvLmes7p2a1BoVvRZEn2eb6w1bCX+YK/JpGP9O199j+m9iJ8mMQGC
         38Xo4Yl48RJqh5urJVimSeoc6wr2/N0koPtEUlV6fCadD6nQ1BJ520pRdZ6Enfdmi/Vt
         TsUYEk3e+Mn1Bz7pSKJFsLUW8y0dESTl9uZaQQn9Cs3FfD3jU2zMLC7Nybzg7Ze9Z3Mn
         6SGEZbBCnkjLc0IbMFtyi0za+8eh2MFoXXhoZYC80l/m1ptyK6haM8RJ52bHV+Ypczq9
         llHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=RuwAtl4T/BQEnhMUj7kO308PAG0hcg8LYi8JBgz3nGo=;
        b=OOno9Mi/Cj8ofJSC7JgO1wHtrTDd28jyVR2NFKMiLW89gTqwdLXs1Z3dOB+YghfDis
         RW9TLG1pwDNwEALIM6a7pWoSwfOl2Qw5RpaW3Kdps5Vz0K0RpZj8DQKBjQwtEaZoT3DO
         KQ2GMg+lv0/fFAcNEoQR8wbBXA//d5vD+plGO7STX10r1ge0UpABOs8La5S/KWZMoBBO
         xnUPa5toIDG0OTVgdTl+uPo4cnzRJFSQirm4pEwysAtYx4StgZA0X3+dPJzKYV3nO+3Q
         ImHWpmqXqZUYEUcMF9cH2yuROU/2MvmM0VkZDsvdpDGKBO90hgfxWloFXZsmGg7TCUTL
         K1Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out02.mta.xmission.com (out02.mta.xmission.com. [166.70.13.232])
        by gmr-mx.google.com with ESMTPS id l20si483586otf.1.2021.04.30.15.50.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 15:50:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as permitted sender) client-ip=166.70.13.232;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out02.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcby1-00CRJD-1J; Fri, 30 Apr 2021 16:50:37 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1lcby0-0003Er-5p; Fri, 30 Apr 2021 16:50:36 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
Date: Fri, 30 Apr 2021 17:50:32 -0500
In-Reply-To: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:49:45 -0500")
Message-ID: <m1tunns7yf.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lcby0-0003Er-5p;;;mid=<m1tunns7yf.fsf_-_@fess.ebiederm.org>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+Yarb9/ltgjgzGllxki6uzGX9RRVA0vaU=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
X-Spam-Level: ***
X-Spam-Status: No, score=3.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TooManySym_01,T_XMDrugObfuBody_08,XMNoVowels,
	XMSubLong autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4938]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa03 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  1.0 T_XMDrugObfuBody_08 obfuscated drug references
X-Spam-DCC: XMission; sa03 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ***;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 397 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 4.6 (1.2%), b_tie_ro: 3.3 (0.8%), parse: 1.13
	(0.3%), extract_message_metadata: 12 (2.9%), get_uri_detail_list: 2.3
	(0.6%), tests_pri_-1000: 11 (2.8%), tests_pri_-950: 0.98 (0.2%),
	tests_pri_-900: 0.83 (0.2%), tests_pri_-90: 64 (16.0%), check_bayes:
	62 (15.7%), b_tokenize: 7 (1.8%), b_tok_get_all: 6 (1.6%),
	b_comp_prob: 1.59 (0.4%), b_tok_touch_all: 45 (11.3%), b_finish: 0.68
	(0.2%), tests_pri_0: 290 (73.1%), check_dkim_signature: 0.41 (0.1%),
	check_dkim_adsp: 2.6 (0.7%), poll_dns_idle: 1.24 (0.3%), tests_pri_10:
	2.5 (0.6%), tests_pri_500: 8 (1.9%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 1/3] siginfo: Move si_trapno inside the union inside _si_fault
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.232 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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


It turns out that linux uses si_trapno very sparingly, and as such it
can be considered extra information for a very narrow selection of
signals, rather than information that is present with every fault
reported in siginfo.

As such move si_trapno inside the union inside of _si_fault.  This
results in no change in placement, and makes it eaiser to extend
_si_fault in the future as this reduces the number of special cases.
In particular with si_trapno included in the union it is no longer a
concern that the union must be pointer alligned on most architectures
because the union followes immediately after si_addr which is a
pointer.

Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 include/linux/compat.h             | 4 +---
 include/uapi/asm-generic/siginfo.h | 6 +-----
 2 files changed, 2 insertions(+), 8 deletions(-)

diff --git a/include/linux/compat.h b/include/linux/compat.h
index f0d2dd35d408..24462ed63af4 100644
--- a/include/linux/compat.h
+++ b/include/linux/compat.h
@@ -214,12 +214,10 @@ typedef struct compat_siginfo {
 		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
 		struct {
 			compat_uptr_t _addr;	/* faulting insn/memory ref. */
-#ifdef __ARCH_SI_TRAPNO
-			int _trapno;	/* TRAP # which caused the signal */
-#endif
 #define __COMPAT_ADDR_BND_PKEY_PAD  (__alignof__(compat_uptr_t) < sizeof(short) ? \
 				     sizeof(short) : __alignof__(compat_uptr_t))
 			union {
+				int _trapno;	/* TRAP # which caused the signal */
 				/*
 				 * used when si_code=BUS_MCEERR_AR or
 				 * used when si_code=BUS_MCEERR_AO
diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
index 03d6f6d2c1fe..2abdf1d19aad 100644
--- a/include/uapi/asm-generic/siginfo.h
+++ b/include/uapi/asm-generic/siginfo.h
@@ -63,9 +63,6 @@ union __sifields {
 	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
 	struct {
 		void __user *_addr; /* faulting insn/memory ref. */
-#ifdef __ARCH_SI_TRAPNO
-		int _trapno;	/* TRAP # which caused the signal */
-#endif
 #ifdef __ia64__
 		int _imm;		/* immediate value for "break" */
 		unsigned int _flags;	/* see ia64 si_flags */
@@ -75,6 +72,7 @@ union __sifields {
 #define __ADDR_BND_PKEY_PAD  (__alignof__(void *) < sizeof(short) ? \
 			      sizeof(short) : __alignof__(void *))
 		union {
+			int _trapno;	/* TRAP # which caused the signal */
 			/*
 			 * used when si_code=BUS_MCEERR_AR or
 			 * used when si_code=BUS_MCEERR_AO
@@ -150,9 +148,7 @@ typedef struct siginfo {
 #define si_int		_sifields._rt._sigval.sival_int
 #define si_ptr		_sifields._rt._sigval.sival_ptr
 #define si_addr		_sifields._sigfault._addr
-#ifdef __ARCH_SI_TRAPNO
 #define si_trapno	_sifields._sigfault._trapno
-#endif
 #define si_addr_lsb	_sifields._sigfault._addr_lsb
 #define si_lower	_sifields._sigfault._addr_bnd._lower
 #define si_upper	_sifields._sigfault._addr_bnd._upper
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1tunns7yf.fsf_-_%40fess.ebiederm.org.
