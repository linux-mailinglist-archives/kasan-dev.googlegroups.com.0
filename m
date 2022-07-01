Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJMH7SKQMGQEIGKOFUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 51E54563531
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:38 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id o21-20020adfa115000000b0021d3f78ebc2sf423501wro.11
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685478; cv=pass;
        d=google.com; s=arc-20160816;
        b=mEMhGKdVl7XdyX3j0ovJmfLXGx8TBXvZLRNShp6iY9VekSchqlKiJN0l1vtCKm8yBF
         tZjI61cqIBLoKwPVzB3r7kwduAb8+zPLXXae9APmUDQ9WMqD3aj6wPeENaZ/YJnc8GUu
         TELpxtQZYfTrr1m/khDzc2xTmSmmFuTkK6E5kn6NmEbXrlEQpL87ReYTN1rrBHDfFbSH
         TSTsreVzcAhaf1vuR9WAQEBnkB020TkN2tuVP5t8pCR/yTrlYw3jI7Gh4TfaNwWnJErd
         QUP/IwpK6+BB5DhJL4wTPuYt9PDSA0P1Rzx177V+jY1Roj4XyaZjifW1MzAeRW895C6e
         2JPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3ULZgkHHwqPCTqfrPhSXwXaiLUpv9Qeweamm0053P9M=;
        b=kS7MI+gHTAOKxWREaZNfCwpNll7/9SwPISN1x2TBQ5eY0zdwxnTU4Hyuvw7I8UseDR
         K1M9qBarQomu6HJDUJtMVTW3zO7t98xzcworyoTd/PGb/sDdX43HvbOp9Qoo4NmF2a9o
         zYrVOSm7uNirUAZFMYEIIUAG9yoATEri2YNqyC9AjOkSVEEaGdcXgCbYRAIjyZSeUjph
         ri6jmU+b2l4cphoeZxTj7OIoNoszSMevnzbrpA6vqvS8lpuCpEEuiZ76VbVxZrtqEnVP
         Evcu5N6HexRHqeFLEhddQHKsSxqyep5PFUprRpOIAPXo9ASqY+RS9dbBCWQ7JlrW4fn/
         j2rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=G6KzvVOz;
       spf=pass (google.com: domain of 3pao_ygykccmpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pAO_YgYKCcMpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3ULZgkHHwqPCTqfrPhSXwXaiLUpv9Qeweamm0053P9M=;
        b=UbfRZwhvpBiKbbmDbqM/NUN/vbK+0lj1tra7NQBpRCjTOGd4Y8zXlw71CINY65Hyk6
         78IRx/uhjz249eJiYPMJkNdNU5Gz5tTJqylQTIimFrxLfjSje2RvM2GHtc/fPr+g+RMC
         2Mtrpo0rpCRWOJ6U0kIMB7aRsGYUIdi222zadKlzUseuH9kibgaMayb5FczAs74Rg579
         2tNX/UQCbsT3OG4g+K8n7CukVBacH0lzmZ2bczOmdjOIS3/KY3edK9zFHbaYQO0I+pqV
         O0C8OzUhD+nNZmQ8bXQYVco0NUmIkBjREzR5Ad0FjP3bI37NJvPR14s7pnQZgKiHBFVS
         PIAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3ULZgkHHwqPCTqfrPhSXwXaiLUpv9Qeweamm0053P9M=;
        b=qr0tnu0H6dFyEJC5s5ZJdzHg02Vuoq7a9N5tPvCZlXce8PnMSxCfytHHRbIKpAbydL
         8PxcsBgJ4iwrsRIAGbdtjOM5jkNsDix/ROwluYpehbs7vLDM+JLBx+N/gN+wptpJrpSK
         zeN5TySm4MZttEQ4tR69cprDQXrEZLjdBSKWjfdAyc0GjZ/R6MY+pv+H3uIG9jsj2RBe
         t/kHGuk+QsNu2WrVb6uunx7U6pH1SESa8PcI3+XzuFJODYOGAqQh5eKbr84sSg0TAH4A
         OFt3zPUMZKQGyw28n1XlztBFviKGVjAXqUctDUK02r2sJH7dgV9tnsCGm3a3mdSM/7Bv
         yfFA==
X-Gm-Message-State: AJIora+nBEgGm/Xq4u57ig3KCgKWoxoEc1zsjKMU+phslLxqmD2EInup
	7F4OzSyfMWMb8SyX8MjQUjs=
X-Google-Smtp-Source: AGRyM1snrm1WWbRPo4O2IwBuWJdjeGQBZDsukiONa1VWAnDoxWafGynoF8hyhyYabdWQqCF3mvf9Ow==
X-Received: by 2002:a05:600c:210d:b0:3a0:2eea:bf4b with SMTP id u13-20020a05600c210d00b003a02eeabf4bmr16994268wml.28.1656685477895;
        Fri, 01 Jul 2022 07:24:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:156e:b0:21d:2eb7:c707 with SMTP id
 14-20020a056000156e00b0021d2eb7c707ls11374764wrz.3.gmail; Fri, 01 Jul 2022
 07:24:36 -0700 (PDT)
X-Received: by 2002:a05:6000:2c6:b0:21b:ad25:9c1b with SMTP id o6-20020a05600002c600b0021bad259c1bmr14470596wry.391.1656685476743;
        Fri, 01 Jul 2022 07:24:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685476; cv=none;
        d=google.com; s=arc-20160816;
        b=k517pxjvKtLMrmdlKcrSYUHWzQEOd62TvMxnALo/PR10r+imjUHMhtdfFqTA/bfYCl
         QyUfLs3pzf7gUSQp3uob/wmrvjSE7pCXAHOeb0K8UQ+aTpBFeSlvJK6yVv8kz3saT4Js
         4sLqlAKqMVu44W5wQ3bXfc7/YDHPUe8Y//w9vOsiOx1tJspPjtGcSGM70zWqu/SktlcV
         0Q6F+Q7rMMaddNMzNS2wYR2IQYwCWZ6dTR/mLTEH+swfyaxmckNE/jKam9XlNaFZj9gY
         a9PsG2gKa0I3D8iB6DfkDGtmIDkrs8o0wfCWv5BKN3GG1zLcmZq8EOiB3D7gGchW4TVS
         CXbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ssAyKoViePAlR4LG6grDIIfDn5PGY84PY+YiOkKWqdU=;
        b=0VPZN1XBzSFnhnmh5BKTzPrUTYaKY1ByS5HS/YNPb52PwP2wby8p4IAGkdTI+QMODN
         Z8jdsI0y5Z5PeW6Xl+sffVnbEznbszGRPlddsRtk/sqAzUP1pqeCT0JP0sGrfcXGgH4g
         tcsXnJzM98eglA9ZeU0BBhPh6918BNPTCZQTs2F3PFV28Q2kGC4LiNF5j6KEnfafepyM
         gb0xkk7QiLK31mKGig5m6X4pD6X4WEkFBuc3yor0h+xuzk9t6i/9YIhTzqNHl2c0tYwz
         TFHHh9zAGePdX3AXpcXSfzg/bvkPx9p/fsvL1WYLhmMORLFUXhQq5nefMYPbEGp9LaZ2
         H8qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=G6KzvVOz;
       spf=pass (google.com: domain of 3pao_ygykccmpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pAO_YgYKCcMpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05600c1e0e00b003a04819672csi299796wmb.0.2022.07.01.07.24.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pao_ygykccmpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id qf29-20020a1709077f1d00b00722e68806c4so834496ejc.4
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:36 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:2077:b0:435:a428:76e4 with SMTP id
 bd23-20020a056402207700b00435a42876e4mr19161928edb.367.1656685476397; Fri, 01
 Jul 2022 07:24:36 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:54 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-30-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 29/45] block: kmsan: skip bio block merging logic for KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Eric Biggers <ebiggers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=G6KzvVOz;       spf=pass
 (google.com: domain of 3pao_ygykccmpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3pAO_YgYKCcMpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
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

KMSAN doesn't allow treating adjacent memory pages as such, if they were
allocated by different alloc_pages() calls.
The block layer however does so: adjacent pages end up being used
together. To prevent this, make page_is_mergeable() return false under
KMSAN.

Suggested-by: Eric Biggers <ebiggers@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>

---

v4:
 -- swap block: and kmsan: in the subject

Link: https://linux-review.googlesource.com/id/Ie29cc2464c70032347c32ab2a22e1e7a0b37b905
---
 block/bio.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/block/bio.c b/block/bio.c
index 51c99f2c5c908..ce6b3c82159a6 100644
--- a/block/bio.c
+++ b/block/bio.c
@@ -867,6 +867,8 @@ static inline bool page_is_mergeable(const struct bio_vec *bv,
 		return false;
 
 	*same_page = ((vec_end_addr & PAGE_MASK) == page_addr);
+	if (!*same_page && IS_ENABLED(CONFIG_KMSAN))
+		return false;
 	if (*same_page)
 		return true;
 	return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-30-glider%40google.com.
