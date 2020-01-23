Return-Path: <kasan-dev+bncBDNYNPOAQ4GBBUEFU7YQKGQERYUX4AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 522A3146DA6
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 16:59:14 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 62sf2544829ybt.9
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 07:59:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579795153; cv=pass;
        d=google.com; s=arc-20160816;
        b=qF+VuYKnvnb2dLhL6jcRjly8Hm5RprTHGf79VT5VoE6Yaul2Q5H/F3gDJ1p8g7eqwV
         CW9qHu7NYU32Vug3TfYlcLNRP8qPZ0VR8cFp1kzymB2p1RxsMaSqn0KqB2JGghbk6X4w
         PCcry5FbE0TuDKRR0LJJMsC8cq9o+93TVXAgdgiyRZfZ7bfThMnNndRlFImn1y4KO2TL
         O/hpj0SjJz0JSlM2p+49b7iMmW/JrQ8nXdhYJpM2FxYpVvNSuboiz3d1ASrU2hVgAd/Y
         kDFWS59s6hXlWeghtju95f9BfgotTYb8KHVXRWBJ14O+oM13pic8taMWdqF46G7JYnvn
         P1sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fG/k9Ki6OF95ylEoRtigQKVNtEQc9HA6ADVxcQ/P1wo=;
        b=OXGLkB2VNAA3NMoFJF0F7EomT7daKeTAnK1XAvKcq+wbf7yMBmY7irzEWSau6yMb/b
         7clD7Ml/ylq3vcp2MdoiW/pq1vAm9r9amQIKWOEV0RS3E7OVHeQu70oiTCljFbikZ+Aq
         YahZV7selAMPQkxkNKbhG9/DePxG3O0F1hKOI+1bLy8S5wK6jXpI1saYPw9gpEgzK3Pm
         nRdCgQucqz8IMx0PL/r3XSJAD2T1ph6WTCKv9VvdietEEsrBpS7savA9IklHO3g3/DhU
         C5gu3wuAb4MT/DklDrimHVIfo4avJRZbdTEhslkkPelFxV/TlDz+KznWVuGZrrTyLWGp
         Wyfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@embeddedor.com header.s=default header.b=p3qDpTJn;
       spf=pass (google.com: domain of gustavo@embeddedor.com designates 192.185.185.36 as permitted sender) smtp.mailfrom=gustavo@embeddedor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fG/k9Ki6OF95ylEoRtigQKVNtEQc9HA6ADVxcQ/P1wo=;
        b=aiGCtXjsvcb/hV09TGD/54okHE4AD2PD14nkBzJOtbMuPEAKaDVnmTmpgmdbNhLZnE
         5OkXA1uQoCA9wlwtRYVH+dRYZEo0BEMF/D5CtpMEhWswzpybjZ6sniDN8TQuVmBzwo3p
         Sc8KV3a7wCu3OYO7H2aFgITjCs+tWJcyK9ExBadaYXRj5tjCXF1YvelNnZQWhBG8HF9l
         lCi2G+us6VO4xEBtpWCETgAwPVj0o5mWpjXZIBpuqe0Zk9nbUFc2OLXE3Tp5iu0FjrzG
         PjlqiOqDIWZ3F0zZAweszgqvLJj81JAANzZ5Y83Q2xUqEe5QEdsx1UWM1CbYp95l7R7y
         8QZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fG/k9Ki6OF95ylEoRtigQKVNtEQc9HA6ADVxcQ/P1wo=;
        b=eQWBukhUsIeX2CB0iOpfrXOYk8ox5/xY60/GusuHLrgnFHEdndMTgtbgw2NiXlO5bT
         HRkGywsrT9O//nzQdkIMQ+h0/0PG69uKlt+AmlIp+kMDE5GTjA0517s6U3bgJ8nPvDio
         w288zV6lhH8P9ykdJHSB9S8uOW4dilIgdoqUuDeYZvhRN46hs/Z1Ks04SNl7F37JLjTo
         kwGY12X2e7qpztHR5X1t6H0JxHXZxFGW/Ff3K6lyvzyCr63k/9MdDbWKqVWYUqMXqDnb
         oZlZNzcUtlVEq4u/gTRlx06F1mQB9B5bI553KjRpqK2I0pDtZ2LEKHb8XVxQr3qI3tjc
         ykMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWNkmXAxrSPaemHfQzbrxVwsr9jtrei1p2ngaNxqgBzl3QToRRq
	Hqe7uRw1fDubMDvlbPcuXSA=
X-Google-Smtp-Source: APXvYqxwQtdJ0xNYGxOhixS1W8G0SmHlpwciQ6M0sL4YLV7mMVYKbe51JKVyz9I7swpXrQuoLeWH6A==
X-Received: by 2002:a81:1d81:: with SMTP id d123mr12363658ywd.195.1579795153080;
        Thu, 23 Jan 2020 07:59:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8644:: with SMTP id w65ls1337833ywf.3.gmail; Thu, 23 Jan
 2020 07:59:12 -0800 (PST)
X-Received: by 2002:a0d:e746:: with SMTP id q67mr12338923ywe.496.1579795152574;
        Thu, 23 Jan 2020 07:59:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579795152; cv=none;
        d=google.com; s=arc-20160816;
        b=ie44oqFzZ1ZLxdarLUV6C+mNU/1RAV7fIuaBDfla40aezVHTiVVM0MA+6s05ljFzWe
         nsQT6LYTEvJTx6MxAvSmlRyF3AyYheUzjoRnma07o0EkLHkSXKCNS9VJQ2hNzaAQDxCU
         8VmSoElbfnSXSXYyvbhgFyLZrn/DQMlvMhn8cncKbVoN5M6I0ieMrc4YqShJwGOXDXwM
         6Y8UF1GncQNrc2x/59bwVa4JrYAYkdlnOrSB01ipvej9hWA+mKKFU3dvYGHinCI52tIE
         CHbFl/sfqEfHttNG8iOLFdgwgetGe7ud1XHjta520hwMC2b0yvjKfW/mhOLN7h/Y4Zih
         zFfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=oP2QJvbUq8Jm9J2za3HLAy5fshYGIjNaVrWjjbn3HQw=;
        b=fyW1Fq0VYCzP2osLGbWiFH2Bnmx+xBFO1UlosLfM73f3r3gFAGWRxxxl0N40BxlrOA
         3BAqolN/R7yxRdcaOolSg6e2MfHagTd4OXcHAejDaiHe1/c+1kFLWU8MR9D7YT63tW8c
         RTS6r/JcrumOjw8M3SsYEOBGFBKRKzuskyzXRbAjbzfzfQOmDd+Y7/+5Uh0E8isGqcLD
         POLClfEUj5W7UKcqrdGFkEFt4f/L3eYwN/PyHcLIu9IlwW2JDBFEHqjqp1tBCm20NpYm
         SVdueHtrNy/B/V1MLGtqD6/RHQHGvUgDkLCFSPdmE59KBmKi75WHfbyGS0RaGmPOPMGR
         i1PQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@embeddedor.com header.s=default header.b=p3qDpTJn;
       spf=pass (google.com: domain of gustavo@embeddedor.com designates 192.185.185.36 as permitted sender) smtp.mailfrom=gustavo@embeddedor.com
Received: from gateway36.websitewelcome.com (gateway36.websitewelcome.com. [192.185.185.36])
        by gmr-mx.google.com with ESMTPS id v64si104738ywa.4.2020.01.23.07.59.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Jan 2020 07:59:12 -0800 (PST)
Received-SPF: pass (google.com: domain of gustavo@embeddedor.com designates 192.185.185.36 as permitted sender) client-ip=192.185.185.36;
Received: from cm17.websitewelcome.com (cm17.websitewelcome.com [100.42.49.20])
	by gateway36.websitewelcome.com (Postfix) with ESMTP id 2BA4C400ECAB0
	for <kasan-dev@googlegroups.com>; Thu, 23 Jan 2020 09:12:07 -0600 (CST)
Received: from gator4166.hostgator.com ([108.167.133.22])
	by cmsmtp with SMTP
	id uesxioio95mEZuesxiC1aY; Thu, 23 Jan 2020 09:59:11 -0600
X-Authority-Reason: nr=8
Received: from [189.152.234.38] (port=58026 helo=embeddedor)
	by gator4166.hostgator.com with esmtpa (Exim 4.92)
	(envelope-from <gustavo@embeddedor.com>)
	id 1iuesw-001riw-CF; Thu, 23 Jan 2020 09:59:10 -0600
Date: Thu, 23 Jan 2020 10:01:15 -0600
From: "Gustavo A. R. Silva" <gustavo@embeddedor.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <adech.fo@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>
Subject: [PATCH] lib/test_kasan.c: Fix memory leak in
 kmalloc_oob_krealloc_more()
Message-ID: <20200123160115.GA4202@embeddedor>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.9.4 (2018-02-28)
X-AntiAbuse: This header was added to track abuse, please include it with any abuse report
X-AntiAbuse: Primary Hostname - gator4166.hostgator.com
X-AntiAbuse: Original Domain - googlegroups.com
X-AntiAbuse: Originator/Caller UID/GID - [47 12] / [47 12]
X-AntiAbuse: Sender Address Domain - embeddedor.com
X-BWhitelist: no
X-Source-IP: 189.152.234.38
X-Source-L: No
X-Exim-ID: 1iuesw-001riw-CF
X-Source: 
X-Source-Args: 
X-Source-Dir: 
X-Source-Sender: (embeddedor) [189.152.234.38]:58026
X-Source-Auth: gustavo@embeddedor.com
X-Email-Count: 6
X-Source-Cap: Z3V6aWRpbmU7Z3V6aWRpbmU7Z2F0b3I0MTY2Lmhvc3RnYXRvci5jb20=
X-Local-Domain: yes
X-Original-Sender: gustavo@embeddedor.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@embeddedor.com header.s=default header.b=p3qDpTJn;       spf=pass
 (google.com: domain of gustavo@embeddedor.com designates 192.185.185.36 as
 permitted sender) smtp.mailfrom=gustavo@embeddedor.com
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

In case memory resources for _ptr2_ were allocated, release them
before return.

Notice that in case _ptr1_ happens to be NULL, krealloc() behaves
exactly like kmalloc().

Addresses-Coverity-ID: 1490594 ("Resource leak")
Fixes: 3f15801cdc23 ("lib: add kasan test module")
Cc: stable@vger.kernel.org
Signed-off-by: Gustavo A. R. Silva <gustavo@embeddedor.com>
---
 lib/test_kasan.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 328d33beae36..3872d250ed2c 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -158,6 +158,7 @@ static noinline void __init kmalloc_oob_krealloc_more(void)
 	if (!ptr1 || !ptr2) {
 		pr_err("Allocation failed\n");
 		kfree(ptr1);
+		kfree(ptr2);
 		return;
 	}
 
-- 
2.25.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200123160115.GA4202%40embeddedor.
