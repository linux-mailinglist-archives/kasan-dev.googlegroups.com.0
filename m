Return-Path: <kasan-dev+bncBC7OD3FKWUERBIMMXKMAMGQEYTT6XNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 329475A6FA7
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:26 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id dn8-20020a056214094800b00498f685a1b3sf5857640qvb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896225; cv=pass;
        d=google.com; s=arc-20160816;
        b=BdZDuHoDT6bN09fSBNQXuROQGwTD8DK55/e1h7R+2hzbZt61evl08iHk4a+Gt/NlSO
         dfdbaxkvISHUpgcR9WPBoSCl2HgRe7P/2YwWdzN1bY7iiqLAvHxQMDZtJKovIZhMs0mS
         +T77aevLXfWuDBr0xv6OLkp0WptwwcpXq2NKST9MToUN/tEJEJKe5b29f5T54BzoDxYN
         dK4uRCZzyJjhWn4J0AZIazhgeNr5votXJPImspUBiNcU6IY1kgVHgyvVV3MDDRI2z3RY
         sfVvnSlsjG/BABa43Jm/2pLf9R7WK2h6Q4yV5oitBd55Jq28Rn0WD2poni9IybDzniLR
         T0FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=INK2TBk5aXG2jOUY5A70qimfGO8ckrzNIQHc5uHhqUw=;
        b=IBySRyP1TB/8DTlnpd4skorjVJxyGm3sC6Xatjgwsqe0UV7GklC3bTlCRG6QHY3gAl
         HwExrBDJD0W8tVgBPLyBuBHHPno6rfIaCeVS+2l/nXnICwd9ELC41igp0P3TeIjXyZQe
         J4W1b9ErFtxVGy8Dhlce5BnykRK36w3ALYvI5iVcdu2cZAxO3W3598rC/cx0ANGevCN0
         BOuQ9WmL3eiQe+3TNNUmnbWC4HuiPU1KKcQlPL74omfcWQxSOFNEk3xTvoRDBKEkI38u
         WcGViUh5CJfZSW9EuR7icQ4Hjn/SJQECaIHGGiZIYz0afLkbmmrnpW9nx0Wa+9fmXCql
         uxKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="kiiww/u+";
       spf=pass (google.com: domain of 3iiyoywykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3IIYOYwYKCYU130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=INK2TBk5aXG2jOUY5A70qimfGO8ckrzNIQHc5uHhqUw=;
        b=mRSrBkVTDVC4v8zBrVq+flmiWqEqK+lCUtofUCXKnZVyqow6wtvXv8WeAdqIqZ1xSl
         AuboK/L+rxzYMWC4gUqRE8y9051zWziqILS3fVjigwYpkqQVGLgizT0beBRmbTectTfH
         2NgfpFZi3AjHOtA6aPE4eaoaD34NgLvP19cbk/XT1x/Sk7li0PtpK5Gal2WLgKtxTvO3
         TUmb1zp4GB5XNASPKjUs5fVpZpfsnslL70JoSZFHv/1grqgjtm0/G5lv4DhRkqmTb/Ou
         mBreDkFMS4a6ufBFfOfT9IC6cp3w74EFZXHwCcC93S7QpdyMIqiKCaTrVBWExaixXZZZ
         Q7Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=INK2TBk5aXG2jOUY5A70qimfGO8ckrzNIQHc5uHhqUw=;
        b=2kVCnVMdF+BmMAGIqs4R7HcZvnKcCCwcgXIFZZeqClNOWmTdJgE8Ifh7eKxHA7lWAv
         lD3axuli7ElMFEMb9RZn4lcRJheH4uEZCAPR/ErgZg+HYi4fkXzOBn7BoWiyq6dG6jVD
         0dkrsR2/pYNZ2Z4z7Y3t0QhyLEz9voUkvSuVFeuRtGNxsRXffCZJk/PN4W2984xxh3IA
         TzOxniLLwBODlzIgJUWn+7ZgYBM0IvKNOpshLoAFqKFBn3j30Huw8EcdBinhGE62Y1bo
         Mw6qMVNoynPPAPGO1fWQbrmEd6kN3eSAQvCH/sznFvfPLcIVe1F/XC/NhL4Sx93B6gf6
         LIHQ==
X-Gm-Message-State: ACgBeo3WKCNq29xufmkJ/z0zU2b/wKji0+sXLkR3AZeaIH+u/llRJjt6
	DpfY8c2o2R7zwTm6kpU2N6w=
X-Google-Smtp-Source: AA6agR7JylAEQIC8fnJtUDTs6wNdV1XIkhvMEG5bkinuz4hC7hR8/BhuLtkrqjwpbHm0BhrC8fZYVQ==
X-Received: by 2002:ae9:e309:0:b0:6bc:2334:cbfb with SMTP id v9-20020ae9e309000000b006bc2334cbfbmr13104334qkf.661.1661896225269;
        Tue, 30 Aug 2022 14:50:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f384:0:b0:497:2b03:d8aa with SMTP id i4-20020a0cf384000000b004972b03d8aals5642001qvk.1.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:24 -0700 (PDT)
X-Received: by 2002:a05:6214:c23:b0:477:a6dd:70f8 with SMTP id a3-20020a0562140c2300b00477a6dd70f8mr16958847qvd.23.1661896224766;
        Tue, 30 Aug 2022 14:50:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896224; cv=none;
        d=google.com; s=arc-20160816;
        b=h6qa2C5MVFd3krm8z8ct1br8L9BKgeMPVM8+nLlwFuSo9bevHAO7TN0DbCwb29uAsm
         lNJplKp1RmfbO04s7D3cKW/BcFL9jig39dmSTKfnS6xFNr/YPss1e8EQgvoO8oZDNLx/
         Jkfd65RD/gNeY8lkFpbCXDOodd4ngEwUcW+qTLvZqmx6FI7AWcBFogDmbC6jfX9LjSJf
         Du8+NpHyPV7Qi4lWT+WLi22fXvKrplkc96ZNAbzd8WlMh5CfMbFvWuMO3ef8AhsDbcqm
         oacVxj7ZG0cs7Bn3taUqmA9kkqiW2x5Gy+xhBywCKBRrWYitFh1T1KqNTRBVEOXwon9Q
         wz3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tbrDSnAu2qp291q6FJVI5HAkVfDwcm9jT2uRBxykBxo=;
        b=Ojbkdd0yZTyFg+kG/TF8hNE9H4/FRm78SrMuM59L33bIu3GNcXB7dBKZdA+9FiYQVn
         0hbC/LHmzTs7hLnRnLl8If15s9Yx/MtFMTxaZ5h3gwpRl0wSlkgsYU3ATIo10hNevTVN
         xcpyfhwk2F3Uk0SStfeHoEbQ8GPCAAoJhQoHSvcgezJFgOKOabfjI1xqHCIeWS6sO/Fr
         7xEUAOOmNCARrlmpYoTWLlHHZzV3Cr03WKSdpPAQ9bhK8ZoH2R6IwrvTbtklr03zkzLx
         z6o1+p5Qi2pEJJt106nweeG8kpYS2j83y6foZqQyfY2SkB3riA0hUjIfITjDFl5BqE8R
         G9Xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="kiiww/u+";
       spf=pass (google.com: domain of 3iiyoywykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3IIYOYwYKCYU130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id ci8-20020a05622a260800b0031ecf06e367si521585qtb.1.2022.08.30.14.50.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iiyoywykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id k13-20020a056902024d00b0066fa7f50b97so710725ybs.6
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:24 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a81:13d7:0:b0:324:7dcb:8d26 with SMTP id
 206-20020a8113d7000000b003247dcb8d26mr16712805ywt.452.1661896224365; Tue, 30
 Aug 2022 14:50:24 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:12 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-24-surenb@google.com>
Subject: [RFC PATCH 23/30] timekeeping: Add a missing include
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="kiiww/u+";       spf=pass
 (google.com: domain of 3iiyoywykcyu130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3IIYOYwYKCYU130nwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

We need ktime.h for ktime_t.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/timekeeping.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/linux/timekeeping.h b/include/linux/timekeeping.h
index fe1e467ba046..7c43e98cf211 100644
--- a/include/linux/timekeeping.h
+++ b/include/linux/timekeeping.h
@@ -4,6 +4,7 @@
 
 #include <linux/errno.h>
 #include <linux/clocksource_ids.h>
+#include <linux/ktime.h>
 
 /* Included from linux/ktime.h */
 
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-24-surenb%40google.com.
