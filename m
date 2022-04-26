Return-Path: <kasan-dev+bncBCCMH5WKTMGRBM6DUCJQMGQEHGACIWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id E9983510400
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:39 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id n25-20020a05600c3b9900b0038ff033b654sf4011278wms.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991539; cv=pass;
        d=google.com; s=arc-20160816;
        b=E2hgME5GK98/Y4chFDzuWqtm9kMiZmxJwT4V37Rbl+/P4xOm56m+XnUHROyHETd5lx
         HDnlNi6UU3Zgivzvn6wyYTNF5VujYsHiD/QIVrpAscyF7nqzh1VPUIxpMfdCiSfAPsw8
         vv+brWK0UvD0IAwiLYjnMQldr7SoBUUldSeZaTVW/zzakffHE3DlQsjrPdOUxJxroI0u
         nbHT1N1dAnuI3nFPKwA4M/+GIjo4+PRd9Xh07pJWIqGOEyndbA09WP26on9L+P03g3VG
         1CRDHmRgXq6SDUdF8XNWph4J0CiIflwhgkcti/br9ASMLD++CT5URHpX4SzQVAfjUA5N
         zlGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=m1BIuFUWiUrLuw0KX8/wxRlOc9nRSMajcmBnOAmwytg=;
        b=tGb5FOS9APmscLcKbVRGB1klBW3GZBJotGcjsyrDgwBXF7v1s/37Crb0UKrRyghixM
         1lfxqIfr0NPZ6UHjp+RMwVjaflCmmJfANQ74rDKkx9O7X0YfgaqMQz2/+U5OALn3DlEp
         E1JvqAeKBgrKG5g78b7iUipXMv7c+0ri0NxCuxZt7oxs+xSO+3er7vWg7OmZsOT7G2X8
         odU1lgL06Eg+tncuXKic6E8wPlHh2t7rydvxSrpgCEkDVx6lNtAv81A6neN3fClqpeV+
         G6zjHNZcG5dF1Dd0L3Jo8fIii3TzOk5gk6IC694iLAtmvXNWzcVbhwXFqYo2jHyQTbXw
         V1MA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y425LRYJ;
       spf=pass (google.com: domain of 3sifoygykca8vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3siFoYgYKCa8VaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m1BIuFUWiUrLuw0KX8/wxRlOc9nRSMajcmBnOAmwytg=;
        b=JEYfTVq7TIxHG73jCZvrzNN0DuzLSBXfDMUdcukhfUJww6Vckx202J1zFUhJj07Z1y
         DKnyEBKQmTkgkGy0ps7L1K536Y9mhsTgsXKXxQ7I+X8al30h2hGveJozmTVv8rC6Pnan
         yb3r8QZgSY77omWF2PW5eYHgkq0aPJdadY7hiNK4ocw1q+WqQ8PNrrTQdvOhiTGESjFe
         vZVGtLgtXiia0JJ3qBlQJkymuoPpnzlgj/0ntxFvpJkCLSu4icC+m80g00B+Fvlc0LYg
         A87xCMjHsusEhCfRtj3Ftk6x66/G9Q3rbMAZNzGyINbzMQn2GlRGHmSTgzXEhV3elC35
         sVew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m1BIuFUWiUrLuw0KX8/wxRlOc9nRSMajcmBnOAmwytg=;
        b=OqvMB5AG4Z23x9lUGEmoV4BjpXYpymctavcK1Wd9Oz0ObVSl4IFPTvWid7V4kIgi12
         JEZaJGHnamD41W4vQ+FH7Y+t1IyPmxpIsWa9/Rj0REeSp9+et/r7z3Yas3+rS3CjiwVa
         HEpyU1OlMiwjBDq3Q2w/K4ci0Gw6nbqYWd0Z1sYx5u7flimK4vLBXPB37szCfE7wlr32
         gwYRQUdNMP2Lfk9j3zNWabqwBIhErjzXt7NyKizm9h9SP/5nMX3622MjNE8MGU9hDbM1
         8Y3xnPQE+ootTlOZLvdz9GTzuAbil4QZdnGisNhg4EI0S8qFiAiTgWUNlKHOSgFAyQaS
         uStA==
X-Gm-Message-State: AOAM531+0jg53w7PJL5hXwvbUrycQzIg+leM+8vuszP+sWEzLGvr9TQu
	yfM7KJ3RixSHpQld2iiV45o=
X-Google-Smtp-Source: ABdhPJw4Ci0uWH5hushtHFzKm2KS9+5VbLsKCYabl/T6j8Ti77ZsGOXTq8Ul4Gi9R2x5/j2jsIDYww==
X-Received: by 2002:adf:e887:0:b0:20a:c52f:e01a with SMTP id d7-20020adfe887000000b0020ac52fe01amr18831749wrm.42.1650991539763;
        Tue, 26 Apr 2022 09:45:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9a:b0:393:e698:3558 with SMTP id
 k26-20020a05600c1c9a00b00393e6983558ls4263008wms.0.gmail; Tue, 26 Apr 2022
 09:45:38 -0700 (PDT)
X-Received: by 2002:a05:600c:22d2:b0:393:f4be:ea1f with SMTP id 18-20020a05600c22d200b00393f4beea1fmr4601716wmg.51.1650991538767;
        Tue, 26 Apr 2022 09:45:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991538; cv=none;
        d=google.com; s=arc-20160816;
        b=Ywwqy1JqJyAEKQoeVrDM+HSadlGaDP+uW45ldNZPwfmZ+3NagjEDAnLmZ3sw45EPkt
         swWGSDWv+TygbQRUQtKUWrXBdjUrJ8RQ7pLmTpD+SEJv4Iz0h0sGWXybtIc5PdvOxipV
         CrY/sLmLDvZ5Zj68VFOFeM5qP1aiPpCIgqfzScPr4vAIybFpXuQ/lc0t/9tAnRViXrnV
         oWU+CeirYzxcqzAvjBF2Ty+YUP15ZQ1asp7XIaepyL9q8Kmy0ShYOUdz/qncxsND2O01
         LXl1krSd+I4CBNAvFI6ohNcVc2w9Z9QWhz3uXURV2YUEWnxHR5nB1Jmp44gf6SLyCZHL
         kzWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=bWOHkFAZUowQhXbgV/15IRTSfhe/pFIeo0hpg6VoqgU=;
        b=k22WfblotiqeTHz+qb5Cv8O8f0OxSFuHFNTqxo156VmP0MiYnGXIdqnDY2wpdKHknn
         IIDjzmPHbivV/NtL+ZCZqX6hYyrsX5Ft80Et2iismCc1NGorob9Hu6b+hjwo93gEUYDY
         Ldfi+23EyBL8Xgu/bn31X7bNQ7+lbCerlDYDTAGpDbXEcQuqNZqV0bhSsZTN0Lk2nRfC
         mm3/tnhpQau8Dz2tFEDZjLJS5ztRtCCgsuIuXXAsLLbOUKYcPqZ0QJyQH+Maqe2UGseh
         jGSOhLeLKiX9qWEqs40aXSOLYX8WNSAppCj52n3Zj3sy4HAiVY3HOZ6PwJHQDcXmQVRz
         JdUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y425LRYJ;
       spf=pass (google.com: domain of 3sifoygykca8vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3siFoYgYKCa8VaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id bg1-20020a05600c3c8100b00393ed6e46d8si117328wmb.2.2022.04.26.09.45.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sifoygykca8vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id sc26-20020a1709078a1a00b006effb6a81b9so9363849ejc.6
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:38 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:aa7:c789:0:b0:413:605d:8d17 with SMTP id
 n9-20020aa7c789000000b00413605d8d17mr25370617eds.100.1650991538395; Tue, 26
 Apr 2022 09:45:38 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:59 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-31-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 30/46] kmsan: disable strscpy() optimization under KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Y425LRYJ;       spf=pass
 (google.com: domain of 3sifoygykca8vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3siFoYgYKCa8VaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Disable the efficient 8-byte reading under KMSAN to avoid false positives.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

Link: https://linux-review.googlesource.com/id/Iffd8336965e88fce915db2e6a9d6524422975f69
---
 lib/string.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/lib/string.c b/lib/string.c
index 485777c9da832..4ece4c7e7831b 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -197,6 +197,14 @@ ssize_t strscpy(char *dest, const char *src, size_t count)
 		max = 0;
 #endif
 
+	/*
+	 * read_word_at_a_time() below may read uninitialized bytes after the
+	 * trailing zero and use them in comparisons. Disable this optimization
+	 * under KMSAN to prevent false positive reports.
+	 */
+	if (IS_ENABLED(CONFIG_KMSAN))
+		max = 0;
+
 	while (max >= sizeof(unsigned long)) {
 		unsigned long c, data;
 
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-31-glider%40google.com.
