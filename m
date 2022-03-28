Return-Path: <kasan-dev+bncBDGIV3UHVAGBBXGUQ6JAMGQE74CJVXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 58E604E9CF8
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 19:03:25 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id h4-20020a2ea484000000b002480c04898asf6248965lji.6
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 10:03:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648487004; cv=pass;
        d=google.com; s=arc-20160816;
        b=XR0K8UvqxRFx+eSjpfn8UEsKnair5M9txTCk9LN2rlmwcewct9Tx2rJheLiOulpOQR
         pUn9+khSxWmuf+vuh63ve/TulS0vB3VFEM2jDfg/mGlqbrAodfFYwWn2/QoL9DX9LI+d
         0ideugwJ9dtnLEF5Oie68AyzAbj+xufH3mpKJjy26jAsRwrawqpzI0B6gcIIwaMjXxy8
         cHDPEpP6x+N5tcDStGluXpTdFAnRiu04qs6feuqKX798p4DrdNGTzpEtGy99nSDtlUak
         moicsG2oS/fSWnGzZxGrMtvbVXYBgrDho4YuvT8cwZyU1bEJ2fbFYs1V3l1Db4QTCmi/
         Az1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CbM0iVMejFksxYK1P9VXjmdkqcZ3eOoODX0TrtX5UiU=;
        b=NopbnjiEpmRNWIwYsbzUsrljStyaETDn8CgRH8uFGpUJvhXlGEOGXbKlCWiloMEMu8
         n7Ovzzaqyp8nUG3vEmWWWGIpSFW97gCRkx8zMgU+F7/Ur0zUO8hq/A1V7WbX/kSpvdta
         njvaLu/cOQiIykriSNh0dcpwHljgRpGUVwTf/G7JLYOUJlerH8k6pJNReT4Bfy3PeDA3
         mB3C+DXO44xrjk/3GdxvF+FQXuXQD0+W5gug2zEexXWI7Ie+9NfW8jo+xqKb+nyH+xVq
         yaUQzoVfHOBMj7BhiJkEXgkEcvAZ0oP8t4jsR7x4bXCPnhAldJCuLpLf2wg1kIrFQ14W
         +jbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Pmt3+lGN;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CbM0iVMejFksxYK1P9VXjmdkqcZ3eOoODX0TrtX5UiU=;
        b=cc7kkxXFw0eW9qB9LLGkgypmizzhBAoMKxDf+21PN75o5qUaruNi+mxXpCPMjBxBo0
         atERM7ggPjeMQZhEZar5zY0IfC1iXaany3KQKruYQBrWPjw46buBKRbUHRLQ+07z3KV/
         wfqoU8fcEElV/H2lCT1farWfTfpgBst6901EgpNMZ+jtqBPssl2Pio1mNlo4nrHrHawC
         5pFsrLfoXahpPB4EyDZ9ILdqGs5hffEsJzBHvJNdC6i4ARFKMmmkplye7HJ+JKFOA6b9
         TWTC5FNlrlc8eQjL8mtxZLZy2npoxzQfqx2Jaa8XboN9ifX5sewGcVFGhBWxI2HGH7jw
         PUXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CbM0iVMejFksxYK1P9VXjmdkqcZ3eOoODX0TrtX5UiU=;
        b=tq/NjvUF0MsJHoOBQznpkt3JCNBAcpCRWPGA2E8VcfBnI8ZSA6fmvV8fM4Cs7eWIrB
         J6KTsUQBXbY/LWm36oAYktFhbo66+pYBIVLRyizLjeLNioSJov2fBKA4AEdYC3YCyXwt
         1Iny17bzs2azoP3WiWEX0/1V3Wroqf5jBFZYwciFoJ/OZgewM3pl84QfOTnxdPqfPmf9
         8LEEUCTfJUvt2yFcwGvcQqmag/+w1TXMuZS+YPOFet2nExes1+vj1Qelsqb81m238BLP
         XIcjtVkVJl0NoTlf4dSLNAHvmac1Fxg8cAJ4BX6VWcdabCDguHbWioM6QvQGBWnadB1k
         SLZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532oRLKE0j0SX7Lff+uZw2LYBFxidCYZP6MNPKPuBhTweyT5VrZJ
	BaiJY+Su21fLOt+ecD2M6KU=
X-Google-Smtp-Source: ABdhPJyYd0A3OJ73tQmEh2srQNzsE/gk432bj3TS4bfFGFViZPArsLkDAv1S8gILEcTdCdkjU6yS3Q==
X-Received: by 2002:a19:e048:0:b0:448:2caa:7ed2 with SMTP id g8-20020a19e048000000b004482caa7ed2mr21240192lfj.449.1648487004585;
        Mon, 28 Mar 2022 10:03:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:3813:0:b0:44a:9ec7:d611 with SMTP id f19-20020a193813000000b0044a9ec7d611ls2168917lfa.3.gmail;
 Mon, 28 Mar 2022 10:03:23 -0700 (PDT)
X-Received: by 2002:a05:6512:228f:b0:44a:2f6f:a433 with SMTP id f15-20020a056512228f00b0044a2f6fa433mr20346991lfu.520.1648487002983;
        Mon, 28 Mar 2022 10:03:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648487002; cv=none;
        d=google.com; s=arc-20160816;
        b=zpo6ZItRawlDJgnut0QEk1ywThgC5cWv7vqm+AznJizcInHqcEIdgkA3vFCTAXT+Qf
         SqAzorGndPDDeA6v2W6IIGGUX96VYj5Norw5V8LLLCunhDCrwXjUPJs46gWLGgGHMTlc
         6rqdUAoZdOXl/mkjLNPVuczmNAoejCmPzCmfVKPiCYKOQNURYX9WhhIGL29LBXvqK1oA
         2sXkYiWsAm4IKQzWmtbhA94olIMOw5RRf00qjIUAyaqeDUvAtHD/tLd7pTqkMLnIaTd9
         9lh1zCd/L9GIm4d36eeN2qgtRneCkwn9zKT7jb1+HGsU8IjbJnIxYZEDoVWv6NZK/87g
         LCYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=srXDUoBEUUPdcjFobaF0lZd9YYmN1yFN4+ozvIVJW9Q=;
        b=OHHKvj398AkKpE1HZX9+m8j+bEtFuLDJICnmwj5rp7g2kg2TjSLkcTkxdYDPK120EB
         65HZaeD7h61n88pEr8jRRsUkG0ADxTjHsoKdi22zzI2IevDjfRDyzP4ILCxkfD7KO/nt
         a7KrrEY8EQtQQUgl+dklXP6uV8yaaqkyjAbn1TH+h4PL65cpOk81iHNmkTtG7PS15a1h
         qr6MBixqJcqaQjCoVaKd2nvAXXLO8dxhtkR7nnlQz1dDwbYLTCSqsDX87KhXH0y3jUGH
         xKy776GSYVj9zWTKU/ZNZTGsYkKWreA9ZZ5lUeHP/CgFVaY6Q9Qs0jUNM8bTPHvr1pTK
         n3ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Pmt3+lGN;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id d24-20020a0565123d1800b0044a28635947si782728lfv.6.2022.03.28.10.03.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Mar 2022 10:03:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Mon, 28 Mar 2022 19:03:20 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vlastimil Babka <vbabka@suse.cz>,
	Matthew Wilcox <willy@infradead.org>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH] mm, kasan: fix __GFP_BITS_SHIFT definition breaking
 LOCKDEP
Message-ID: <YkHqWKRRtnQuAVa/@linutronix.de>
References: <462ff52742a1fcc95a69778685737f723ee4dfb3.1648400273.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <462ff52742a1fcc95a69778685737f723ee4dfb3.1648400273.git.andreyknvl@google.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Pmt3+lGN;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2022-03-27 19:00:23 [+0200], andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> KASAN changes that added new GFP flags mistakenly updated __GFP_BITS_SHIFT
> as the total number of GFP bits instead of as a shift used to define
> __GFP_BITS_MASK.
> 
> This broke LOCKDEP, as __GFP_BITS_MASK now gets the 25th bit enabled
> instead of the 28th for __GFP_NOLOCKDEP.
> 
> Update __GFP_BITS_SHIFT to always count KASAN GFP bits.
> 
> In the future, we could handle all combinations of KASAN and LOCKDEP to
> occupy as few bits as possible. For now, we have enough GFP bits to be
> inefficient in this quick fix.
> 
> Fixes: 9353ffa6e9e9 ("kasan, page_alloc: allow skipping memory init for HW_TAGS")
> Fixes: 53ae233c30a6 ("kasan, page_alloc: allow skipping unpoisoning for HW_TAGS")
> Fixes: f49d9c5bb15c ("kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS")
> Reported-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Tested-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YkHqWKRRtnQuAVa/%40linutronix.de.
