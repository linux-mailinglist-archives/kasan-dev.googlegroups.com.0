Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVFZXOBQMGQEJJJQJ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A1873580C9
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:37:08 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id w8sf819695edx.0
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:37:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878228; cv=pass;
        d=google.com; s=arc-20160816;
        b=CuFRQw9M3Y5U5+V5UrjdKOj1FBBsBSENVY+VZE7f042mcuLDKJB78kCWTuLucMFUS9
         MSj6IgzA9TcsPnWU0OXtYaBKxnafcJ1G/3wwx3Kq6gNHRA59kK+p9piEHCSfyya9Qsuo
         Tsycff6M06wEevmTH60Ka1N4OsPOHCPP7dTr6/nPxNr/i2GlXPoKdEik7WHL6MP55M34
         dsAmtJjno2zrK7Zzby/UkhAVOQe0ryAjZuKChPYo0IbPePyp20vVSW0IsLcyE2g69TLm
         hzs2L+QYkEKwrcf0PTWcJWyK9WdvJPzO+WYC0C3UiUJgeu4io/x8sTFyYiXoPCqCLhVw
         Fm0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Ag0A3eboM/VPa4p8PPzXtm2CSfxQP2yrkytIop5lTTs=;
        b=ngxquopI2NGDfR7SSQpJGAvwdWiXnrYB11Xypq8T1dZZAZ2xgYnUqTrfeK5Tf3iZcK
         gc5TEWWR4U0NiazRAhoi49IgVlU01kmHAVU6RQPAVjyE3TntZXgm1AvObl7a6/SX/iL2
         jWHGcTuA7gED1s/S9ALTodZ37MKiA7mdn8Z0K18C2y/3sDILyL9QC+JkuYM6CtcTuwqe
         QwCqeiBuEiscaQRYYQij0PpQS+3b6Z84v+5JFh/CHiskTT1C7helWrbY5W6KrX/vcMvj
         xy4wsS8U0dM73EbfHCAX0+mtm4W+Wc7JwtjESbyTokcYNM1/BTL2YRkQaXh2q8v4EJm2
         xnYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="M6Xf/Rby";
       spf=pass (google.com: domain of 309xuyaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=309xuYAUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ag0A3eboM/VPa4p8PPzXtm2CSfxQP2yrkytIop5lTTs=;
        b=lLQtVIK/Y3Y5YPCWETyU7k5MUHyhpX14DiNIooDIwhHD2Vayy6C5F0n1VZRuNI25lU
         YL48x6kjQx2ZON+eSWkls3akPLXcdpjZjxaNh81fImYHQd54DAVaJJ+VaGNhWCNd1Hgc
         RNk1ZqRdNAtKFwifcySryRN+6GIQYLqrpZ6dCSwFNynZ9MfUwzM57CH/9qk/onsyC2B5
         rg07NmMsz6z3sVML70NCjmK5vLjsk39lOTdxv6gJtpCr5YW9Ba3Alpp107x7OsZOVYeR
         T/HHukk+L4IBBmgPKeZkZy1nvXeY+akIXja9+6TKMam+YmwoZ9lzwpoRPP9zaq2ualfh
         0z/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ag0A3eboM/VPa4p8PPzXtm2CSfxQP2yrkytIop5lTTs=;
        b=dITA3Ia6TLuOT0+e9BTkf4vCz43TVaHuMqYPcdslQFg2TisVe+VHgkTBz+lO/hBQRy
         eASdVix8Lfu+DgCgko1qEcOXdqG5+Fa23APpCs6z0357lmUIQYxyAWriV+N+9SE3uAgp
         wYvZhYY//sC4fqYJ02q9uXj813+IGfuG7QQxBFuwAAoqzd5MNz31nHwvovAQvo+/Vye/
         DxklR6zd3L7kSgo1g26Ilt3DE8XltxL5jxkPkDq1GZBYddHIEceB1Hin/Z2OqaeHfVlK
         xUpnvVrVfuIJ/4n3g9u63tNF1A5k3CyXud4x2PuzZEi37ElQlLuS8uojb7aAdSXVckZ4
         GdpQ==
X-Gm-Message-State: AOAM530r3cFUVpyqa+9X9NIiuz6s+/yCz5jfWtM+ZnMIU3JkIuZZRFq8
	fGX+8AZY6oM/EIdJ7DaUxGQ=
X-Google-Smtp-Source: ABdhPJzSpAd1kEvqoNVr21GjCL0FL5AOA0oOVze8kBHbB7z/hyxviKBMCn9lvOFZsSBD26nWRNiSXA==
X-Received: by 2002:a17:906:935a:: with SMTP id p26mr5933637ejw.521.1617878228434;
        Thu, 08 Apr 2021 03:37:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1901:: with SMTP id a1ls2949250eje.0.gmail; Thu, 08
 Apr 2021 03:37:07 -0700 (PDT)
X-Received: by 2002:a17:907:2bd9:: with SMTP id gv25mr9529964ejc.225.1617878227509;
        Thu, 08 Apr 2021 03:37:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878227; cv=none;
        d=google.com; s=arc-20160816;
        b=zixWU8SH/MRavXv3xmG+PniP4Mu1eNJ9ITZ0qAYZsmq1mR5KsReW1B02/nypIpy1wE
         MwDrO891yvt8ntqwN0XEtGhaNI5dP0BSANybCUaaiflOik8EXRF+/kXY7wGkmkSgPmba
         hUy0/sRmJ1UWmg/m8Mk5So+v+kmwQ9bFz9mM568dny+PHHKllKhrUoNBrIEaOHdyeN39
         By4ZL3vzUhfNZpsQg49YPZqgx8TxWvtwdFbRrvlmpoKvWONNXhN9aXSRn619YSv+Didc
         yQXCTzEjRwPL3NT2qBuFgTNJRdjs8++4I6u+MTuJJscI87oqMcdpYQ1b6w0dko/R3khU
         wgAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=dgjyTod8e5NlTRHP8hFBk5cuF/ijHRvQheYc8gyMq9I=;
        b=Xp4rA+8RdsHMzrKv8DmcCrYH/bwK3lA4BJ5P1ulwoiRfP3NnUF1ZLTP+VyNlSjRUnc
         x1h6D1M29KxIrW/YVarwzBRf+uwa6aCL/+qhBx03a4CP9XgWeLvypvMNJKXt2gvRs1Sn
         EcYg8Je+LK9sHVDRvl2RutwXKPUBJk9VcbvVmNoMyPROEztYd/IF2dG/hO/66u9VTHdF
         l5dYxjTEbzQGzDe3cFPDpJE9qLeAXOTvO9LBm5dcg+Iu03i62i67I11sOkwYBNkoQCcT
         7Z/M7VVpH+UJZJAY00vdNo+aQH4W0NAMf1rxQ9YtLoLaw1eUAR/XZ+UvGN+fBT3ltbLy
         3JKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="M6Xf/Rby";
       spf=pass (google.com: domain of 309xuyaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=309xuYAUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id m18si2827459edd.5.2021.04.08.03.37.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:37:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of 309xuyaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id b20-20020a7bc2540000b029010f7732a35fso3168984wmj.1
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:37:07 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:a05:600c:284:: with SMTP id
 4mr7768831wmk.24.1617878227289; Thu, 08 Apr 2021 03:37:07 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:36:04 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-10-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 09/10] tools headers uapi: Sync tools/include/uapi/linux/perf_event.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, oleg@redhat.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="M6Xf/Rby";       spf=pass
 (google.com: domain of 309xuyaukcviy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=309xuYAUKCVIy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Sync tool's uapi to pick up the changes adding inherit_thread,
remove_on_exec, and sigtrap fields to perf_event_attr.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Update for new perf_event_attr::sig_data.

v3:
* Added to series.
---
 tools/include/uapi/linux/perf_event.h | 12 +++++++++++-
 1 file changed, 11 insertions(+), 1 deletion(-)

diff --git a/tools/include/uapi/linux/perf_event.h b/tools/include/uapi/linux/perf_event.h
index ad15e40d7f5d..31b00e3b69c9 100644
--- a/tools/include/uapi/linux/perf_event.h
+++ b/tools/include/uapi/linux/perf_event.h
@@ -311,6 +311,7 @@ enum perf_event_read_format {
 #define PERF_ATTR_SIZE_VER4	104	/* add: sample_regs_intr */
 #define PERF_ATTR_SIZE_VER5	112	/* add: aux_watermark */
 #define PERF_ATTR_SIZE_VER6	120	/* add: aux_sample_size */
+#define PERF_ATTR_SIZE_VER7	128	/* add: sig_data */
 
 /*
  * Hardware event_id to monitor via a performance monitoring event:
@@ -389,7 +390,10 @@ struct perf_event_attr {
 				cgroup         :  1, /* include cgroup events */
 				text_poke      :  1, /* include text poke events */
 				build_id       :  1, /* use build id in mmap2 events */
-				__reserved_1   : 29;
+				inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
+				remove_on_exec :  1, /* event is removed from task on exec */
+				sigtrap        :  1, /* send synchronous SIGTRAP on event */
+				__reserved_1   : 26;
 
 	union {
 		__u32		wakeup_events;	  /* wakeup every n events */
@@ -441,6 +445,12 @@ struct perf_event_attr {
 	__u16	__reserved_2;
 	__u32	aux_sample_size;
 	__u32	__reserved_3;
+
+	/*
+	 * User provided data if sigtrap=1, passed back to user via
+	 * siginfo_t::si_perf, e.g. to permit user to identify the event.
+	 */
+	__u64	sig_data;
 };
 
 /*
-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-10-elver%40google.com.
