Return-Path: <kasan-dev+bncBCXKTJ63SAARBVO2S6JAMGQEO65VSKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C5374EE01C
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 20:05:10 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id x1-20020a50f181000000b00418f6d4bccbsf94283edl.12
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 11:05:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648749910; cv=pass;
        d=google.com; s=arc-20160816;
        b=YHbolzdJ/RpEG4wylrjo78NgW7jiHUsiXfig45ZzTr88mjsyl/tdzy7/XKLWEWJGg7
         daz8hUVa2UdJkwYp48yAhOzoTIyfm01ATT8+npGrHZNSkkE+t6GTaFmq4mGVljg1Rv9k
         3Zu0zn0GXSuIYdG6jI/JMI8X4FIYvGO9l+vOK8nPJ/5i8aXYNlPmD0m01/i52RVLQQKJ
         k5+vvkRFsHq3Wu2zPeGk7+6jVPzhlKxQgkwt35ZTi8FhlGIiZcsqCqC3mX7ZJbU33Acv
         O0Wgq2SmCkTbD0RighgpL+pARiBRYxWnTzV3bNl/cE7j15M0u7CEfs74BzhQNCe1DDKS
         nMUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=yUuzr4Gn5hiHL4yYobNiTH25iFKYz02tl3KBlQYj1pY=;
        b=TRAyYUcD3i5DY0db/mUQ1WGootoM33AmdCoGqipxy+fUyROxHN3omM71w6ASVdxj0Q
         DHoE0VobbCK1E/DFeoR4i6OdXGPxy651EEtD3FmnEdv1D7SGODCmYDzbKRM31Bk89jzz
         zKxYSBfc4uj/Q/7Uw9x6E5P6ydRT3hh6pALAPRsq/yi8KGLYhGCVWNomP0HwMHiaNoL3
         nibJGuToW5Vpn53aK9/Ec/r4/0I5tzhT5k8WiI1WKARsF+CsSwcARTlXUpWc96st7BwQ
         73GTtE0TmmKHhzr4fz2n8AZ9plsPF+PPoTELxijU43SmpW0ksISp8fdd/yLa95+Kz50v
         S0hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wc1Hwmen;
       spf=pass (google.com: domain of 3vo1fygykcv8kldfhedlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3VO1FYgYKCV8KLDFHEDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yUuzr4Gn5hiHL4yYobNiTH25iFKYz02tl3KBlQYj1pY=;
        b=LQn1NDKGXqgB/6YUW23NT41CI7nWq1dDSVrYn7eosOhqVISROaQk62BRLTxVkxAA3t
         cZA8M9yqV8LfHBMzjGoptp/m15+Pd4v13G/BxHl6vXiORRWULlq5KODSix03VTYfGeZh
         BhcxlU/nGzlVgrjRL/WQrHW9RyXiuI+GNr0+oOsbq52YXxT5lAPqGoRFfO60HbT2PuGh
         3SL7E68nt1tZg34IDK+YMQTgCL+TqOl8/zvNmwAQced30tCTIIWbi7U3Y3lh+UXIOpo8
         3H6qCyWdUsnuMaqvOZG209Xij278YhUiWO/Jz54hsDC3ljwxeg6HRgSzZWgE31Sc9yT1
         6ZhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yUuzr4Gn5hiHL4yYobNiTH25iFKYz02tl3KBlQYj1pY=;
        b=CRKL7caUQUnWQy3KgFF/eBjaYUKY9vgNz5sJEm0/Nabx26a3Y8nUDhDaJFebLXXYRv
         BxHx6M3l47WLYU/uv/OK41QLqhtdEPJuFJJO8LI0UJ6LNfExM3I1NP9h0yk/JKZuYkfH
         V9qo8BIYH5CAWuQdPK8lXUpzja4QWfP6W3Ijyv2EA71MMRqZk5CcU2VCnJDfpciSvdEQ
         xFmzHZoKA6ie9rtGEXk4d9/YXO4+5Ri7fwuzM9X5YZP0yqTJyaepd2oltTW6UCGGGWfP
         9O0CRNxqef9MBxz41/ELXk0o0CUylTw+2OlA59JPFgDbAhl0R5U2sYNPPm8/uG5g4Jc4
         qtAg==
X-Gm-Message-State: AOAM532vq/awEI9oipzC2TMtJiQFZonEOIToIYN7kPf0n/0hqx+10vnl
	UMyeKFYsx6+SaXPtYTzqEFc=
X-Google-Smtp-Source: ABdhPJwt1op9sMdtl7o7WdvlSW8hI+0051M4lXI4rAQoxuGH5F2B+6BFqzljMLmmGsPXPs3M6pdfwA==
X-Received: by 2002:a17:906:ae0b:b0:6df:c7d6:9235 with SMTP id le11-20020a170906ae0b00b006dfc7d69235mr6146636ejb.664.1648749909998;
        Thu, 31 Mar 2022 11:05:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d1cf:0:b0:403:768d:84b2 with SMTP id g15-20020aa7d1cf000000b00403768d84b2ls6208027edp.1.gmail;
 Thu, 31 Mar 2022 11:05:09 -0700 (PDT)
X-Received: by 2002:a05:6402:11d2:b0:419:4da5:ed71 with SMTP id j18-20020a05640211d200b004194da5ed71mr17684526edw.272.1648749909076;
        Thu, 31 Mar 2022 11:05:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648749909; cv=none;
        d=google.com; s=arc-20160816;
        b=0nN12Cq0rFppsF4RX+UlLOAqVOJv72ZUmgt46CqI+kGE+nWauWhrnz8dL3Ye1KO429
         KAwctAGJ7xmvFRbMQd1QVhI3++erg5Rx3UJdo2c0i58HYxRbnwb+TNMJ6wKuVGPv84pQ
         pdF4ucSgGjrxC2TGV2Dcq8nssU7eXgAbihxNTGRs6pJl6OL7K7o8UE6v3n9V2kycLJwH
         QgjNTami7O0Q3WAdy8dyinv+cgLFZPD4ZH7YoNk52xgR0CsYqF4utC1HVJUjt3JYsYhI
         wXAROOdUxJuj0vpsn6xcNYVZABCnH2vSCZc/FwtMTk22SDzQhA6qmshouRGth/QysD/Y
         2gnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=15hcCIpQC0VqBDHPsAp6yPhi35cw6G3wETqd2cbLIoY=;
        b=xQX79sAdqvK9DUyl7b0rEY1eqXeaua8cJwcCxK8tGmAr3ux5YzTKh1BF8XGpGnvnS6
         xJ3j/NENZzBqV1uEoPLeqBzYUJpcJT9hfyszvKNmQshZbs7VlbQSsOPCutHjYT9jcxS7
         plF0gC5+Zd467toD18AXcYzTURRdXp4YIbx6CkARI9f/LH2bVq0FdzzvEZDx6Crt8YSS
         ahVOMQIQVQ/XUXIeS23RTTnF8VE6uMR3YTODUD5+YXyF2MGgJ5QeyzUi6AVCGsMBxdM7
         TWM/fBQmvZ6K+mQiZraaLORCiTTcr2mtcF0F0KSEEqslCuIBVj3NLMkNDdWIyTsCIera
         zM7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Wc1Hwmen;
       spf=pass (google.com: domain of 3vo1fygykcv8kldfhedlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3VO1FYgYKCV8KLDFHEDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id m4-20020a170906848400b006ce698a3afasi19615ejx.1.2022.03.31.11.05.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Mar 2022 11:05:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vo1fygykcv8kldfhedlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j67-20020adf9149000000b00203e6b7d151so161712wrj.13
        for <kasan-dev@googlegroups.com>; Thu, 31 Mar 2022 11:05:09 -0700 (PDT)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:adf:f78e:0:b0:205:85d3:fa33 with SMTP id
 q14-20020adff78e000000b0020585d3fa33mr4966519wrp.675.1648749908645; Thu, 31
 Mar 2022 11:05:08 -0700 (PDT)
Date: Thu, 31 Mar 2022 18:05:01 +0000
Message-Id: <20220331180501.4130549-1-nogikh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.1.1094.g7c7d902a7c-goog
Subject: [PATCH] kcov: don't generate a warning on vm_insert_page()'s failure
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Wc1Hwmen;       spf=pass
 (google.com: domain of 3vo1fygykcv8kldfhedlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3VO1FYgYKCV8KLDFHEDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

vm_insert_page()'s failure is not an unexpected condition, so don't do
WARN_ONCE() in such a case.

Instead, print a kernel message and just return an error code.

Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
---
 kernel/kcov.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 475524bd900a..961536a03127 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -475,8 +475,11 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	vma->vm_flags |= VM_DONTEXPAND;
 	for (off = 0; off < size; off += PAGE_SIZE) {
 		page = vmalloc_to_page(kcov->area + off);
-		if (vm_insert_page(vma, vma->vm_start + off, page))
-			WARN_ONCE(1, "vm_insert_page() failed");
+		res = vm_insert_page(vma, vma->vm_start + off, page);
+		if (res) {
+			pr_warn_once("kcov: vm_insert_page() failed");
+			return res;
+		}
 	}
 	return 0;
 exit:
-- 
2.35.1.1094.g7c7d902a7c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220331180501.4130549-1-nogikh%40google.com.
