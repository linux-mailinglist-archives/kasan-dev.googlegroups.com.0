Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWVBW36QKGQEPVM3Z2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 861F32B0E6B
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 20:45:31 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id p3sf4213349plq.21
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 11:45:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605210330; cv=pass;
        d=google.com; s=arc-20160816;
        b=p18In7L7ngwSbSRHwPjhFE0RSE2VpouaMO5LsYyAdD6H2jP3E+bccAmUzYF0mKczjl
         +pqPC67RZmarQhdfVePpO7hHcgPG02VFTehYHWdjAyAN9/a4XmgfBeUi9FO/YUeXgrCH
         gOzQxMWMx1iibTBkP+h5V6o72y8KxsMintzdD9lxr2CCBJan+kaI11tg7hvXUneQiDLU
         2xXrSFEDCKJBFBYfB12DtrSVe0DJgTrm+CBeiakuQOvi0LJqjbzSGrepsiCJ943a1Kou
         ywDCdtuJUwMOrQOWyIL1RG87Xp3pMPnfTY1Rx0teUhclWqG70PRtgKNuWHzQeuWwKI+v
         AlVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kv4Ujm7jvfCurRettzNwlaGOE2gQPPt/YPxvuEBVqus=;
        b=S+QLwZTFEWnSJWwfD/lZ1736MsToSRXxRF/GSoiqXYS2tnumCAjKpawyn5NFyKaawl
         UcpJegnI1O74jSJTkFDfaUi+nUTvWt9WGEvI8to2lBtXts87u7/Y++/riwPawQVAx3M+
         df8vEg4/Qgnrm01eGV2Ok+Hw8zIHxmloU4Sr3+JBe5XR7uD5AU/qu1kl6tmioVvcbXoa
         en9G3Bihwl8m28f+X31IEuqSgAZk7hptK6182CeQsAqHstz7WadNalPse08OCY8kkHz8
         UgPB+RSTvzJTQVpAsS75p4OXwEG+9JMX41/OmtoF1y4XbZz4lYvBu8tWtF7UX4lfXIEz
         5afA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rKHdDyXn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kv4Ujm7jvfCurRettzNwlaGOE2gQPPt/YPxvuEBVqus=;
        b=WsSb4Xp5KBxK+SLGoOlOv8QaGWiE3jLWh3TS430Swzgrpd+Id5Hgt/d5B4GF/Dz39H
         n+17JeiWVC6ShfE8iGZe96MkqQ58ug/VKGbdXRzCgTA9hvn056tWb2P8b+Kfe8AtgiJu
         e1FKvEYWT/Hz1moPEqofIk+/TEtEM/hcJv2ZIuRGzhtp+99HSiNdJc1DC5o4USC7P/OH
         lfM0eKElFbu/7o0VD4Pa79mQyZzssn64UT6Tei4G7SHHyNOjV4OdTSjYeoHos0tesy7+
         8vrG5V4BJnb13eTUg1Bpr7ou9SMPhrZLZy+W0qgAJcbA4oez8mPgOBMLkpRFiTbZVB+d
         8yQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kv4Ujm7jvfCurRettzNwlaGOE2gQPPt/YPxvuEBVqus=;
        b=Hj9kcG8DZWkbYkYmwmGsU4D/uXWwoGi6vBp/ZuzAAu81pKfJ0LpkbDdgIgEFodXqx1
         dwF/dwklJ8lgDzufTLvLoXOaDkWne7T+NisbHYeQJ1DBxMtOl/5B01R8i9wFdp4gBdrL
         s017QH2HG+umH6xSbMEzTKRMm25Yym3ewTTyhj786qylYWcpD6zuDeqkxRE+gF56gLzi
         x+NQXvcc7Y0Mj+SxqJqwQIP0vVnZpPRNbwlVQJRIlADzme80dMwszkHBuokKZaKpspTU
         Mw5twLDLCzRu0AOYdxhk3XhOsjNI4YazieR/f98YNDjnQXt3oaKQ8mTuQsgElv6ulGIe
         t91A==
X-Gm-Message-State: AOAM533fcyn/2jgO40BpPBYbv7RD2GVDSlqJ4PdKbNj7VoTRW27ghRQc
	MMPVRBCDWULFI6+dQY6wNw0=
X-Google-Smtp-Source: ABdhPJwReXCvT+3xHFQKGCufFUMuQZ0iO2cqLF5/jaiFeVyBQom+pNOlRSf4TGKle7BIavwBCjkZWQ==
X-Received: by 2002:a17:90a:8992:: with SMTP id v18mr881419pjn.192.1605210330298;
        Thu, 12 Nov 2020 11:45:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8616:: with SMTP id p22ls1354503pfn.3.gmail; Thu, 12 Nov
 2020 11:45:29 -0800 (PST)
X-Received: by 2002:a63:e04:: with SMTP id d4mr919161pgl.101.1605210329806;
        Thu, 12 Nov 2020 11:45:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605210329; cv=none;
        d=google.com; s=arc-20160816;
        b=0qG6Wb8Z8HYpVEujGB49S7Bt84kICM88F0ogq1oxf2dtfJDQAXELnXCQy393fJwbPv
         8YRW32BmdUAltW9SiPh9/aSy+yOB/q7MERPn1TX4QSl5S87O+GGvX04u6hA/SRwzy8hw
         xCjkaZ7XXjW/bsc5tlvFBTSsoFl3JMUS9J7Gb/iVIcCdDCPGWLiSwOWy12qcDrrv7qpt
         DCWW3z1Tph2zFC9F5tA8DhtrUZaeYfsa2Xakttk2RqG4Nglk9c8TCxawo3ZHBpaxnLCS
         js4inHt6ubyfNGSMT4zAFAC7CtzRrWcoo1nkaVCaQMFtnZq+5wQ3Y2Ft2WoUZ6H55b3g
         k23Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tUsjnJsE70MPGpys5UT1OEoJSxFeQtN6aLTMo3hfEjk=;
        b=DfnHYDnb8SMv6KuAiQ9+U+cSn+uHJJbsKOEpTuy3X8NoFx0KhphsbKfJTdQHuEhUSk
         TR+nOgRSuyi3MDcL7lc4085CyOdgvuM/Ee/MisWjV2vb6JMMVjcLp/yIzOtcu+oK5QTW
         9s/ooHm9bPE2lp7vnRC8cReZi8oJUQw2PIfqkMvTSMtruRkgE4UKaMDxMAbVN2G9kDFJ
         Ceo5pY/OKabS2iwERQwLpKzSlAcQ+J0jhvT5tTDtwctpogPNK9TY8PafOiTHT5mcb737
         xe3Kp+G2CiH7Z8KxgWRpBML9Of2wlW9F49zvYR4lvpZr4JVDF8/pcaHsJmf4hS69mMSJ
         61NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rKHdDyXn;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id d2si471839pfr.4.2020.11.12.11.45.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 11:45:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id e21so5065863pgr.11
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 11:45:29 -0800 (PST)
X-Received: by 2002:a05:6a00:16c4:b029:162:bf9f:6458 with SMTP id
 l4-20020a056a0016c4b0290162bf9f6458mr947513pfc.55.1605210329356; Thu, 12 Nov
 2020 11:45:29 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <0a9b63bff116734ab63d99ebd09c244332d71958.1605046662.git.andreyknvl@google.com>
 <20201111174902.GK517454@elver.google.com>
In-Reply-To: <20201111174902.GK517454@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 20:45:18 +0100
Message-ID: <CAAeHK+wvvkYko=tM=NHODkKas13h5Jvsswvg05jhv9LqE0jSjQ@mail.gmail.com>
Subject: Re: [PATCH v2 10/20] kasan: inline and rename kasan_unpoison_memory
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rKHdDyXn;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Nov 11, 2020 at 6:49 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > Currently kasan_unpoison_memory() is used as both an external annotation
> > and as an internal memory poisoning helper. Rename external annotation to
> > kasan_unpoison_data() and inline the internal helper for hardware
> > tag-based mode to avoid undeeded function calls.
>
> I don't understand why this needs to be renamed again. The users of
> kasan_unpoison_memory() outweigh those of kasan_unpoison_slab(), of
> which there seems to be only 1!

The idea is to make kasan_(un)poison_memory() functions inlinable for
internal use. It doesn't have anything to do with the number of times
they are used.

Perhaps we can drop the kasan_ prefix for the internal implementations
though, and keep using kasan_unpoison_memory() externally.

> So can't we just get rid of kasan_unpoison_slab() and just open-code it
> in mm/mempool.c:kasan_unpoison_element()? That function is already
> kasan-prefixed, so we can even place a small comment there (which would
> also be an improvement over current interface, since
> kasan_unpoison_slab() is not documented and its existence not quite
> justified).

We can, but this is a change unrelated to this patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwvvkYko%3DtM%3DNHODkKas13h5Jvsswvg05jhv9LqE0jSjQ%40mail.gmail.com.
