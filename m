Return-Path: <kasan-dev+bncBCALX3WVYQORBKWPZKCAMGQEEBQEXLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B1A95373D46
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:55 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id f19-20020a9d5f130000b0290289bfcbd479sf1220537oti.16
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223914; cv=pass;
        d=google.com; s=arc-20160816;
        b=H6/qhB5aMk9BU3521qkXC5fi8uXnXh1QRZ/Hs/h5M66R/ylkb6RV3RAvmI1sJW+kdG
         HDD87COkknNEo1KTZH6NsUOndQMtxn3N+a//d9zAtuehF7L7yFBZGisOBgzi48/kWiEl
         rcrdhlEaflbLNfe/X7pIdb2FmsO7fGEBaCsUqVbOm7N+fBTbR610lButd2mu3AcK4u/b
         8ZFAJ/HypkM6+dJx7Wus+bEnw/ubt15YrUR2WZ7cEWxNGtphmGY2eVJjvVVGGQeYIIYX
         8A2JTL1GIYSu71PP5h3PusM471naYrruUzzV6jAeZbQAVoFYwe6U1Xq4T4HYRCzcoQ1j
         L8QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=Fe97yhlMKLIwOhTIe4a/16kb0PBrfqqCTZ+3dF+vTkw=;
        b=WP5Qi4Vg/zZupXHk8rRyVMk6Mm5liH4WdbOJWX5pkFDmbYE+ub8+36qxNR4Z6m3Z4F
         jieAzpua8F3kOPWS6qpY2NJSVTk8TgJFgwkAE6JInH4u5HY4IrVKVjIq7IquXliXJsHe
         sPqOeWWb3EA/0SlYpiKVOyEfMa0ft4uows21/0o2CHqLw4Iyx9mFM4PchSowIkAGcP1I
         MYNqAJxtYw5fQIHnb3Q5PArd35G0wNJhZnf9kHAKXzRVLAsy2OXCpMbFcnbJZhPkvmbi
         PkN9Jk5TaUBQao9cVIuxGeVS4fB3oRGKrcDFcV0RKTzBpySGlAsXf/mOSgDvNUJ4S88G
         piwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fe97yhlMKLIwOhTIe4a/16kb0PBrfqqCTZ+3dF+vTkw=;
        b=RJYSZDg4z6M8xeqoKO1WytqhCwCUwG/uWppSG/7iQ5co+TQQv6A2FmteCjWzAdOj9f
         CN8Yu4MSTFaa1XhHL6bLcAeeV7QUgW81t5sV1T6A8DHGgMqhL5PzrtBxGciFY6oBiWme
         Hz8L1JKY5opztuN0r4G7OZH6mxNK9TJei6+XV2rZCjxcvhV+iJUh0S5FOmkrFg+RP+l2
         YSzQZpfroELadMQLuIByNy27Rwbyv8UB2xggyzsN9MrRtQEqYGAd+JkdvpTjrITpUqJg
         wSmJBkQtZYdiQAHceJuhpMS8mvYZf++5Vd9ZaIqkO7CawR/sMQTfMVZlWHOgF4cjqEoq
         Lw8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fe97yhlMKLIwOhTIe4a/16kb0PBrfqqCTZ+3dF+vTkw=;
        b=ApCl5NAQtOmKuF0jQXCWcdHsK32wyrQsd1832cHjQVKq81QKRKHZMQxP71gqP2IGbn
         lX91wvTHL8v3XjrAj4603o5mai7xOVwM04YWSUjqbUVqjfnMunmS7WuAMLHLSGVAzfkW
         6TNXvZVa789yL3pUSfSozfxrP0DsvwGwvh7Oc85ck6NZsPtijdPvGtoSmydTc1lItHxt
         nQPakl986DZFvb64Qb1xM8MWXVQpzvo1XM6gr36XmpDc+390aJHpW/GgbDJSJsvz5zw4
         xTBPFv/Qc1FDhHar5NzpC6lc2V2LvANXn9yxNBtEmCDi2usbDaOyq/lq1CFnuPXNm145
         Vmvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ubZwLAOFBadpb+uHTdeh7PrCkHhoymjBOsqMAWEAOHvkoh/hc
	kdN6pymmqwVTEA593sI805c=
X-Google-Smtp-Source: ABdhPJwn5zTQ+uI7s9jCwdMI2Zd+UZ6OqKcZHp0Ze7So7t/a4prmPMtA4gQnEWwPDryQYFTRDU7Usg==
X-Received: by 2002:a05:6830:2084:: with SMTP id y4mr25021777otq.114.1620223914727;
        Wed, 05 May 2021 07:11:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d487:: with SMTP id l129ls1361633oig.11.gmail; Wed, 05
 May 2021 07:11:54 -0700 (PDT)
X-Received: by 2002:a05:6808:1482:: with SMTP id e2mr7259907oiw.138.1620223914384;
        Wed, 05 May 2021 07:11:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223914; cv=none;
        d=google.com; s=arc-20160816;
        b=wI25X1H7YGPXh3zyDHECiObIaP2w8u3xwwyIJd5JKz9SKiAbwAvbp8z/qMxp/n65d4
         joWpiaGlUkMCrK2HM9XvYZeJ/KiFn9UPp3L6jgyEQAbFtjnm33+koElfnsTdg/ja/vev
         4ufAsqv9j4YvqAUIBx8u6m/IRHNrmlR8yFV7IX4UAYIMpd1Kyl/pl8vI4IrppNgU94xd
         +lf36PnZ8Y927azciraMI/7LaERzskS6X3GdWwHFrh8jfPi3W1NrKZ49xM5AQLYbSrgC
         UKDy/MTpWnE4KE542a9ZbdORiTVmXEtnHmXx/qnT5dxuwFXJ8vI5zfUu1ZmXr4HUrXuE
         qDCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=EHdkqU+1ZCy/UAEDJBKXhLkGVcjM9FAct6jFBcw9M9Y=;
        b=xXIurfG5AzAYJZIZypCkz1mtilqdyweGzucXvqX9jCG341DCkRxkMxg2dRDt608znN
         DBzvVp3XXiSK+6w9Sq7K3nzsXR3opmzj7L5IC4dsbDsnSZKgXFDJ8Uy3G7/XqGa6WkGJ
         fue8gPX2SRf2nBs0w956Qw1Zu8+l8H2xqdGsWf17470eqm+hZaDSLHnVYVNP446PYf/l
         AXHoZ0sTLdyscpGPIXEzUFnGk0sKEkXkPCVeTVeYqSl0nl+kO38KPb1iIvTOnGFX5EdG
         eknjW5BBzC9pZB/GqIEnxTD9ELBgqaUZ2wbcPdyS4l58QXSTsYfvYgCQ26RBGG035goW
         NVtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id c4si720785oto.0.2021.05.05.07.11.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFl-003DPE-6X; Wed, 05 May 2021 08:11:53 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFk-00007y-9b; Wed, 05 May 2021 08:11:52 -0600
From: "Eric W. Beiderman" <ebiederm@xmission.com>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Eric W. Biederman" <ebiederm@xmission.com>
Date: Wed,  5 May 2021 09:11:01 -0500
Message-Id: <20210505141101.11519-12-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210505141101.11519-1-ebiederm@xmission.com>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1leIFk-00007y-9b;;;mid=<20210505141101.11519-12-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+ZMXXVL6ruQ7cgP0DEKoYUOz/jMeRC+JY=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: *
X-Spam-Status: No, score=1.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,
	XMGappySubj_01,XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4992]
	*  0.5 XMGappySubj_01 Very gappy subject
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: *;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 510 ms - load_scoreonly_sql: 0.07 (0.0%),
	signal_user_changed: 8 (1.6%), b_tie_ro: 7 (1.3%), parse: 1.38 (0.3%),
	extract_message_metadata: 17 (3.4%), get_uri_detail_list: 3.1 (0.6%),
	tests_pri_-1000: 15 (3.0%), tests_pri_-950: 1.16 (0.2%),
	tests_pri_-900: 1.02 (0.2%), tests_pri_-90: 132 (25.9%), check_bayes:
	130 (25.5%), b_tokenize: 15 (2.8%), b_tok_get_all: 6 (1.2%),
	b_comp_prob: 3.4 (0.7%), b_tok_touch_all: 102 (20.1%), b_finish: 1.01
	(0.2%), tests_pri_0: 320 (62.7%), check_dkim_signature: 0.77 (0.2%),
	check_dkim_adsp: 2.4 (0.5%), poll_dns_idle: 0.44 (0.1%), tests_pri_10:
	2.0 (0.4%), tests_pri_500: 8 (1.5%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 12/12] signalfd: Remove SIL_FAULT_PERF_EVENT fields from signalfd_siginfo
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Content-Type: text/plain; charset="UTF-8"
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

From: "Eric W. Biederman" <ebiederm@xmission.com>

With the addition of ssi_perf_data and ssi_perf_type struct signalfd_siginfo
is dangerously close to running out of space.  All that remains is just
enough space for two additional 64bit fields.  A practice of adding all
possible siginfo_t fields into struct singalfd_siginfo can not be supported
as adding the missing fields ssi_lower, ssi_upper, and ssi_pkey would
require two 64bit fields and one 32bit fields.  In practice the fields
ssi_perf_data and ssi_perf_type can never be used by signalfd as the signal
that generates them always delivers them synchronously to the thread that
triggers them.

Therefore until someone actually needs the fields ssi_perf_data and
ssi_perf_type in signalfd_siginfo remove them.  This leaves a bit more room
for future expansion.

v1: https://lkml.kernel.org/r/20210503203814.25487-12-ebiederm@xmission.com
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 fs/signalfd.c                 | 16 ++++++----------
 include/uapi/linux/signalfd.h |  4 +---
 2 files changed, 7 insertions(+), 13 deletions(-)

diff --git a/fs/signalfd.c b/fs/signalfd.c
index 335ad39f3900..040e1cf90528 100644
--- a/fs/signalfd.c
+++ b/fs/signalfd.c
@@ -114,12 +114,13 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		break;
 	case SIL_FAULT_BNDERR:
 	case SIL_FAULT_PKUERR:
+	case SIL_FAULT_PERF_EVENT:
 		/*
-		 * Fall through to the SIL_FAULT case.  Both SIL_FAULT_BNDERR
-		 * and SIL_FAULT_PKUERR are only generated by faults that
-		 * deliver them synchronously to userspace.  In case someone
-		 * injects one of these signals and signalfd catches it treat
-		 * it as SIL_FAULT.
+		 * Fall through to the SIL_FAULT case.  SIL_FAULT_BNDERR,
+		 * SIL_FAULT_PKUERR, and SIL_FAULT_PERF_EVENT are only
+		 * generated by faults that deliver them synchronously to
+		 * userspace.  In case someone injects one of these signals
+		 * and signalfd catches it treat it as SIL_FAULT.
 		 */
 	case SIL_FAULT:
 		new.ssi_addr = (long) kinfo->si_addr;
@@ -132,11 +133,6 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
 		new.ssi_addr = (long) kinfo->si_addr;
 		new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
 		break;
-	case SIL_FAULT_PERF_EVENT:
-		new.ssi_addr = (long) kinfo->si_addr;
-		new.ssi_perf_type = kinfo->si_perf_type;
-		new.ssi_perf_data = kinfo->si_perf_data;
-		break;
 	case SIL_CHLD:
 		new.ssi_pid    = kinfo->si_pid;
 		new.ssi_uid    = kinfo->si_uid;
diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
index e78dddf433fc..83429a05b698 100644
--- a/include/uapi/linux/signalfd.h
+++ b/include/uapi/linux/signalfd.h
@@ -39,8 +39,6 @@ struct signalfd_siginfo {
 	__s32 ssi_syscall;
 	__u64 ssi_call_addr;
 	__u32 ssi_arch;
-	__u32 ssi_perf_type;
-	__u64 ssi_perf_data;
 
 	/*
 	 * Pad strcture to 128 bytes. Remember to update the
@@ -51,7 +49,7 @@ struct signalfd_siginfo {
 	 * comes out of a read(2) and we really don't want to have
 	 * a compat on read(2).
 	 */
-	__u8 __pad[16];
+	__u8 __pad[28];
 };
 
 
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-12-ebiederm%40xmission.com.
