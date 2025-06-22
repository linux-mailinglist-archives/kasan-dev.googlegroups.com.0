Return-Path: <kasan-dev+bncBDW2JDUY5AORBJNL4LBAMGQETX4YPHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EA70AE3301
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jun 2025 01:45:43 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-32b3a3c5cd0sf15549011fa.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 16:45:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750635942; cv=pass;
        d=google.com; s=arc-20240605;
        b=bHKbT2bTKoTBLZiwpL9CNtVZFCPpbFZkEz4ovamyV/d922z5n4tkl1ucgn0GUAk3+N
         dHZLfsKCuLRPHw/uEqkM+BO3iyaBCHasbpfS2HzDFiScwe+x0HXsh/8qdPv9hqZ+F+CS
         5t509yfKLF2BM7YXg3rDIGcOnP57n3hnHzXiEgrF1o7OlEy2ZBuYLW7t1OYsz6TE6UYn
         qpfJ9vop/IZ8vIzS0inlc6lQ2mOR6/40wCSwaDEOM4lP63kv61VvQhxQrgMO0rJqcwjm
         GyjghRlIo2089d1SkX2Y4c7bJUpqsWa6w4rLtWCj/moAeG/No0ds5iCpMo8PmPQj9pZd
         dyJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=F5VVk1BuZobFMmPco/oAQ9q/oyrUBCBkCwE7dgwAdm0=;
        fh=p7xd/UsOdA5dxroqk/ZVr4GDPg1JPhIfU0xYhfCz6jM=;
        b=MNVHgUfXQOA2/ICreBLU0IlC2smgSDrUw74/p4bLl0+BDX67r7VSZ/49hOhi6e81Bl
         E8Xrv0iHQF/PlKCGESf2yyVkUADMUOmU7UeuFHS96J+2Mh7YFCO+Uhd0aad9NPVSKGMV
         9VvEZbegf/PflvMgJvXfUBRa+xHjCLL/76WR8fvjEu4YQI2K4Zo9OdR9aWGMY9J5NNhE
         2E5HPygDijlZwCvtuhtkHozBtrY26tM7VMUvnDEGMw8LvFn8qEXmDyfghLIDtifKMBHT
         fvEGPpRgpFSyROJ89ku3MCnedIw91xLRthgZjXreVPXtHFe1no34QN/mx4gJf2i6MKxA
         aZnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bBwymnFm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750635942; x=1751240742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=F5VVk1BuZobFMmPco/oAQ9q/oyrUBCBkCwE7dgwAdm0=;
        b=sFhYQhCUwD+kPWrc6BhrEwsZpnoJoXmBUOY7aDny6y277eWyVwBF2psjrtEolY6MqC
         xSI8T+BcKmzvTq7VEKvANy+R1MvWpF9e9OOnkqzb6Ajot6fGlBcMf5QCeXoM23dvbi/Q
         rqpj5TVJJQ7FlL4isUASEiG+KjBpKQtu2pXWi632BUxc327hXjUsn6+Qi5erwE4GERZ2
         BXgTFq2mYHB15oIRqNISoW3pxRcjU9y6cIum9CZYvUwycQlLC5gxztH/eC9iA+1WukQs
         cGzbmLCOPJJZlq26/L04RFmVGyu9N08beXQGYMdBM2UDyetpecSKz8uheIiArO1VX2U4
         vtSg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750635942; x=1751240742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=F5VVk1BuZobFMmPco/oAQ9q/oyrUBCBkCwE7dgwAdm0=;
        b=PAyccQxFtE4u/nPypKDuLFCUzsvnbTHFnmyo25gdOKfqK2snA3/CnRnQ+PUrTPEoRm
         UADyn87xwepIrnoOYN0OSLWKYNq5Apy8yeq56bksOXw9Tkv4lOyzi5PMIl+pRxqEQgcb
         enQxIVmUe/7IvEqz4iS9f+xVfSyqIO2b6M7IMoViZ5bkipEcr+Ogd2GL65HE8Q5/ZCwg
         ptB7zxrRsJx+MrmhsYWuLPd/Z8TCxITqJxc4Mu5gKgN/dEtBxKlCW3OUad1hFSMEoLqd
         8dRDhwRjTW1mgN+Ek3I5B4GS9xOdFdtwJn7XXFbfdkM8TypaGLb537uuzZ8ECgLuI8T9
         wcow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750635942; x=1751240742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=F5VVk1BuZobFMmPco/oAQ9q/oyrUBCBkCwE7dgwAdm0=;
        b=WCiGS6JECM93Ve4JpikMHArjIYXIfcDkDsV+wX9QRlFhmdWijcj18t/ZoYH/f8Indl
         DmDB8jqnvlBGqfVbhnewbFjta8ABmhexyuG0n7R9iWxD6xm8mhxVxaxKUUj1tIpaQct4
         0akrT46loxvCDLyObi+4NRgV/6/nR/sHiIHM7ywcldarWfko6FqX2sE8v2/Ol/ZIDwmX
         6TvVoLCQGg6ZLuOeImqzSWIiAUWqsyb9/iLI9aKAvTWsJZ3FTWmBBxThCB9y7kKJLTLd
         uMNvBuip0Iw8Mn/klCw6zdKQ2pXMSlVyPcptVlHCjQ3ZlWfVX7/INhok2gC6cnoWCk4U
         Qq3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW42qNnKcqkVJPG8G6eilSAD827z8/WIZTGuFiXqK9lIsHUzVLEGa8dxQV9awno6XX7d7AUlQ==@lfdr.de
X-Gm-Message-State: AOJu0YwozR0kEgkJbj5B+rQ9iN6igK9624YCbo3HtBrYBqd6NXc/Eqfa
	SscOlI4mCL9VSJOFtG5VZVA0r0UaCHjE2iQELu/mTKwNx0gp7aWn36He
X-Google-Smtp-Source: AGHT+IGBlnnbaobrofsdIO67560Ofo2Fp4WPisFZg+9mnRo8bIzhqvf7PUYKZXgu2U0Uw3KD8nIgVQ==
X-Received: by 2002:a05:651c:111c:b0:32b:9220:8012 with SMTP id 38308e7fff4ca-32b990316bcmr27771871fa.21.1750635942189;
        Sun, 22 Jun 2025 16:45:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcn3ATFE3sJRJCHC4qP9qPtdRMYGkFIorYBxYUSvNzZEw==
Received: by 2002:a2e:b90e:0:b0:329:947:b67d with SMTP id 38308e7fff4ca-32b8931c17els4118371fa.0.-pod-prod-03-eu;
 Sun, 22 Jun 2025 16:45:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVFOenVHdhxoRnfwpWXZyvir3v1CSPWETwv2pssLnTT0lnePMparf4BneUsrF1viIqYOZFuDyTDCM=@googlegroups.com
X-Received: by 2002:a2e:a37b:0:b0:32b:7ddd:278d with SMTP id 38308e7fff4ca-32b98ead06dmr25062881fa.3.1750635939419;
        Sun, 22 Jun 2025 16:45:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750635939; cv=none;
        d=google.com; s=arc-20240605;
        b=TRPoV/x2rbOehazh0ILt1zvdMl24fuxP6pUDJpowd27y+HRm7kD6U3JOhO/0SFsQx5
         77RiLJ65MU14DADibTtCiQz9RbNCDR1LoHuViBZ1usZo+pj1HnryDYuTw+xRGc2V7m1+
         tvUETBuTVSxM4DJ9SodR6Xi1zkZrcWs2Vc0meoRhzHlht9BE15pS4EqHVyphDVIPJdnj
         48ZW+sHpCWa05imyHUo68soG00dW8geLvLIeCLI1gXnD2g2mkOLgOj1rlzLvZwTcsHgT
         +UCui0UFuqdCta+k62uT+ZJdiZ3pSgMIVDJ7dfp5j9Oauw6aUr1vYbt+7GzB6YbZdmru
         +XOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AfRSgbFZSy5dkhaBXEq2u/k7fzFxoV0b6ZxvQq5cauk=;
        fh=/qeuziTF/4E2KSXUhp8hzwrIdyzOAD4cZ9svFE2EQIA=;
        b=GGmBmK8Hxa485qUaR5d2e9dhNWMzqQaxyLRYmBkJef7kke6pTPpv7eZ3blcQFm6V6o
         B4iO0+xRSmQTrgo8u1Un7UWk7cRkpGIua9xo68kIuq+6K7XlIf8/mWLCuX2QotJjommP
         WS7Dx5X5P5yXjYcjkAHbdZBHoydrlLwlNWCn1lHSPqIpblz5hzzncttdRvML2doykA9o
         HkGm3TxwlRqQhy3OF2mowylHUbQui+df4cIa0+w4UFRel5CPcMik8fzuBwTwCfOSP0Ya
         Sw3XYbk1hol2Zd41983f7ONQBSUk4tyaNClP1A0u8v65XRWz9ix2oRzP+LKzsPhLQqnO
         wK3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bBwymnFm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32b980d3316si1200601fa.6.2025.06.22.16.45.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Jun 2025 16:45:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-3a365a6804eso1907133f8f.3
        for <kasan-dev@googlegroups.com>; Sun, 22 Jun 2025 16:45:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2ZXl/v5MY/+T+ynAUN+qC6zk2kf6DDv9nI8/CIRYFvqQFdlseo0aHyFUx+LWijMXtpEpe5nzzc2Q=@googlegroups.com
X-Gm-Gg: ASbGncv09vhyypjZqf4LTdkvDyxxZXweTaz3VCnST0aEEvyEs2ATJoDndFNzHrTTO3I
	Og/v227PAAD5Qq421JzUdx3v19fwf1uUcWxGZ0PMtrQkVDYXlItsYrQ7NsRP4/rihjP7YJidro2
	qvvECvR+8I+4zZiyejkvOzUgbbj5G0/AdGEiYxnbAaqH87Vw==
X-Received: by 2002:a05:6000:4812:b0:3a5:85cb:e9f3 with SMTP id
 ffacd0b85a97d-3a6d12fb438mr8377371f8f.12.1750635938566; Sun, 22 Jun 2025
 16:45:38 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZeb4eKAf18U7YQEUvS1GVJdC1+gn3PSAS2b4_hnkf8xaw@mail.gmail.com>
 <20250622141142.79332-1-snovitoll@gmail.com> <20250622112014.76bdd8929ecdb1c1fb3015b5@linux-foundation.org>
 <CACzwLxgSBszyEr4zRqMbnoA0PEnZQNy8_ZKTMtwm-Nkho5MePg@mail.gmail.com>
In-Reply-To: <CACzwLxgSBszyEr4zRqMbnoA0PEnZQNy8_ZKTMtwm-Nkho5MePg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Jun 2025 01:45:27 +0200
X-Gm-Features: Ac12FXwUkZLlD3Swe_7wD6CkEWUE3IVyAJ6jtFRMciaxOVoXB7zY_DK7oRwjgAQ
Message-ID: <CA+fCnZce9dB9WLXuw+gteoR2+Brq8H6zLo8JaLGuVg=Rfmj78w@mail.gmail.com>
Subject: Re: [PATCH v2] mm: unexport globally copy_to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: arnd@arndb.de, david@redhat.com, dvyukov@google.com, elver@google.com, 
	glider@google.com, hch@infradead.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bBwymnFm;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sun, Jun 22, 2025 at 9:09=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> I haven't verified this, but theoretically, it's a handy
> =E2=80=9Cwrite-anywhere-safely=E2=80=9D ROP gadget.
> Assume the attacker has already gained an arbitrary RW primitive
> via a UAF/OOB bug. Instead of stitching together
> prepare_kernel_cred() + commit_creds(), which is a common path
> of using exported symbols to achieve privilege escalation.
> This path needs two symbols and register juggling.
> With exported copy_to_kernel_nofault() they can do this:
>
> /* Pseudocode of exploit for a ROP stage running in kernel context */
>         struct cred *cred =3D leaked_pointer;
>         rop_call(copy_to_kernel_nofault, &cred->uid, &zero, 4)
>
> copy_to_kernel_nofault() disables page-faults around the write,
> so even if cred corupts a guard-page, the write will not crash.

Attacker can use copy_to_kernel_nofault without it being exported as well.

So I'd say this patch is more of a clean-up of exports.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZce9dB9WLXuw%2BgteoR2%2BBrq8H6zLo8JaLGuVg%3DRfmj78w%40mail.gmail.com=
.
