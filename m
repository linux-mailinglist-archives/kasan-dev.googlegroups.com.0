Return-Path: <kasan-dev+bncBDW2JDUY5AORBJNJ72VAMGQEXEAUAJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C6C197F65F5
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 19:06:30 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-da307fb7752sf1586103276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 10:06:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700762789; cv=pass;
        d=google.com; s=arc-20160816;
        b=pzduf6XwjsTHJ3GndvA1sTxofQ5i8U4Ol80C8QZ9RDprHeDQDOvJjRAk/fpgIP3rJy
         8tLcF4mjqRxtoksN37WXhZnEkYoLG+rGt7qC/NmaalTy2j/Pi75KXGE9jzCcBBbSfkL+
         cSWXSxtxT4fOVEnPVEPRjwqszs8yhdY1eUawK3xfGzVO1Gd8k5F2Ix7tR/5CZpj6jHml
         eLT0hRyI1dea3paRIsOedknefzMGjGCVfNSt/YLyHYDmthMyNixMhLa3wr9uPCYjxJxw
         XGWVlnOnglRCxmoS73LTkmieRZHiLKShLY+SWMsI6dW4Nf3hyTgR/bOYn3FlgF9ThqtQ
         bD0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=uZRgNr9awQd+SPFiuWUWv0DF/H11DrYwM4j0ch+3SU4=;
        fh=YkVDR0A+vozh5A2Ys2bfc3KlovOzAXgaZ4cuYbKRmSk=;
        b=s5hWM1Kzr7DNZzlV2TpVLTDDloli2nG4S+Czg7KS5a2+6/uE34yerUo5ns0P99VSYC
         brgXCr8hMht8RTKty3ZWN592Ss8s02zCieE6aty7MoYAaNb8CW2nw5mhdXxoA7wdWmlG
         4++6rF7eXPEn2vv1hsm5yz4t3TLcsgRedUIHNlpUSxoRu5BRdiGB+BySB8k24aH5Mc1G
         7qwmLd5Q7duCZ0AlMCbf6gRnWTeyuyV940Kz5hCrQ6l21l1llDjRQV/xJGMQDEj5C6M6
         nGQWqSdxmwgqvMmETQ/3QDud+Cw9kq+aPdld5sF95yE0mBeKagwtLQyKbY9erYOIfbnF
         XKAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="I/n8wa+2";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700762789; x=1701367589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uZRgNr9awQd+SPFiuWUWv0DF/H11DrYwM4j0ch+3SU4=;
        b=jlpkRi3oysztvtnG595MGUo5+1xrL6kH9XOoOMcNXXgL9Rj0XYFMniaLQdLyDsjGMh
         Rcn9c1VYF9oJC6ufNjCv6dQZCAZ4zDDJcCON6kNrfiTrEl8BMAsFNgiJKXTo3fCaTkfS
         xR89zV6LtO9vw4JWb90GImpB/iv4PpPfNKfafyVaIlvQKbWBL+ozHY87sGYqUwPIe0B5
         /29GUfsk5t+XjbnPWGjEgTTbRrKth+6INH98R1WFD0GTOsQiuUEZc/MLqRLsPrdE16zS
         jC3jjmed4FjZhnk1zamzeNVRcnWaz4F4SDUlADu5QRbC54MUZSZJlK049VNlJ3CWfsP3
         7wbA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700762789; x=1701367589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uZRgNr9awQd+SPFiuWUWv0DF/H11DrYwM4j0ch+3SU4=;
        b=afLQIPJS9fXb4YDhtb9pHqWw1UxhbZ1WPoSsReAOjW68taT2hPrtz5ThTHCfzc+7S/
         7j5FYPrycbkU7UOLV1ExXUW+GNoDSlmLiedAsM5vEUck8d5+8D/eB2fREfTAlCIBAp6I
         ll54AhAly38o57N9hqvd0PVINu7MqskQuTK5XjMyZpmm+fgF3zsOV0nxH2qsFx+jmeOh
         SjjnRSekR9hIJABbZZzjqUoI4CuXYOTJrPugJbuyrMTMKL2S0hOlpPZ+p9wnaFEnn/ZD
         4HKt73B7BlfqxrWaPAjU33bxHeWBSABfmJ4YLcUALDUFJSFeo/Ket4RjonXt+UjF90fP
         nYXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700762789; x=1701367589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uZRgNr9awQd+SPFiuWUWv0DF/H11DrYwM4j0ch+3SU4=;
        b=DqzXLpNMy5dOvitZc9J3RfFTh83U1wGIRvV3Ct5HRRcAdhBLnSTM6pilRKDP3Kr2f1
         IBc6iv1EzSCZx97+bUGbsdwOT4mBEyzmw5qlOJC5L6OAdjYBrKypKiB4hw3WwCz7BMhb
         AHCV7rCmfy3pkljPs5d81A5JD3pRHuz8xTkmyLNR/QzEqWEr+ZVlcKtDMd6UiwGU6V8j
         OlLveXDQ++w+/OKpeOPMbF0KEcoKSCRsl19okhxXIkg6XDr6PC1/XWyYTB43umxGlqJG
         B3qrcPpRDf8jXW51ntLqhsP9M2K90Xi3GGFt2yXMLxCQQAVQdpjfAViu6aPs8uR2kV6O
         jx4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwVbus9HUMudON0Un4ITLAR6t63ilYQHYIirBFl0HP7+aMFjrqM
	Z4fkyfMHcEKCBD2TDbR1fXU=
X-Google-Smtp-Source: AGHT+IFluQR7AaVyqvpadY0eh3lmYhgo/tp57xvnsIhcL8dOvpANmsNhVJdLg6Ds3PuLQ7WHity5EA==
X-Received: by 2002:a25:734a:0:b0:da0:4afd:61f9 with SMTP id o71-20020a25734a000000b00da04afd61f9mr31866ybc.54.1700762789368;
        Thu, 23 Nov 2023 10:06:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:33c5:0:b0:d80:8d0f:1129 with SMTP id z188-20020a2533c5000000b00d808d0f1129ls1321940ybz.2.-pod-prod-09-us;
 Thu, 23 Nov 2023 10:06:28 -0800 (PST)
X-Received: by 2002:a0d:cc0e:0:b0:5a7:e6fb:39b with SMTP id o14-20020a0dcc0e000000b005a7e6fb039bmr161750ywd.1.1700762788578;
        Thu, 23 Nov 2023 10:06:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700762788; cv=none;
        d=google.com; s=arc-20160816;
        b=a3utw/SOhpIC0vheqbVCkepHq4c6qvbL7/taH/U+R1/Lq1ZSOLTrxDOiReG8mB4rhR
         hco7llbwPPCoSncLjs83bnDrbR6yLwS9NvyxOVn9h03Fi12063NvMji7rtUfKLYBYC1t
         aWtQ6XzHhCypeBV9vHiIV0MeZYkVBMdbry0CDst77VE3PpdxJiFhoqZnfaPu6wO8Cpvi
         B+7/BZaRUo5xspXxxWs8LgeENi6lfhF/oco8dMyC3nA5BHdhZ/Za/pZlKRVqLrFTkzFT
         2v+YDaj5SqEDjllG+Snbqf3ZBzpRlBO2PZmgfp4zZnTqc/gHxU5i0pJy2DkM3UmY7ISh
         RS1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HOe1NePRnmjI5/xj2NE8BgAqPHEuVYA8qvj9b+OSxE4=;
        fh=YkVDR0A+vozh5A2Ys2bfc3KlovOzAXgaZ4cuYbKRmSk=;
        b=XLauV0Xr83u39rU693AYxOU3pd7EzYKMQH5YDKMhAd1b0hc/HpECoWq1quF3KJsw/t
         3Zj6xiOj5drpjOMFegId47cdOL/IFpxSbfqpeTEJE361NGsHQ/xxmUZ4/ld/mgdFo4pE
         uGUKj6xXcdXysG/MUPWIXzS8bhHtgcdkzhujfZh/jtA9eXFpMmsFc5UsgvDSTmm1lf/3
         nvHaMBR1ZIPAoONEqXSJAvkvKw0uPKXzIrokyIazsyaM9PBvlhjlkZeoklkf/OPiWgPC
         iBy122vjrSAYvu2acPMEQBQ4tzIWObQZjcWs3qgUi5VTn0bAsqWaz1UqLLRu0aOFiXbT
         lx+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="I/n8wa+2";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id x74-20020a0dd54d000000b005ccd9a64bc7si175462ywd.1.2023.11.23.10.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 10:06:28 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 41be03b00d2f7-53fa455cd94so746035a12.2
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 10:06:28 -0800 (PST)
X-Received: by 2002:a17:90b:3a8d:b0:280:1a19:6dd5 with SMTP id
 om13-20020a17090b3a8d00b002801a196dd5mr162675pjb.36.1700762787678; Thu, 23
 Nov 2023 10:06:27 -0800 (PST)
MIME-Version: 1.0
References: <cover.1699297309.git.andreyknvl@google.com> <9752c5fc4763e7533a44a7c9368f056c47b52f34.1699297309.git.andreyknvl@google.com>
 <ZV44eczk0L_ihkwi@elver.google.com>
In-Reply-To: <ZV44eczk0L_ihkwi@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 23 Nov 2023 19:06:16 +0100
Message-ID: <CA+fCnZft0Nkc2RrKofi-0a0Yq9gX0Fw5Z+ubBfQy+dVYbWuPuQ@mail.gmail.com>
Subject: Re: [PATCH RFC 14/20] mempool: introduce mempool_use_prealloc_only
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="I/n8wa+2";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::532
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Nov 22, 2023 at 6:21=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Mon, Nov 06, 2023 at 09:10PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Introduce a new mempool_use_prealloc_only API that tells the mempool to
> > only use the elements preallocated during the mempool's creation and to
> > not attempt allocating new ones.
> >
> > This API is required to test the KASAN poisoning/unpoisoning functinali=
ty
> > in KASAN tests, but it might be also useful on its own.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  include/linux/mempool.h |  2 ++
> >  mm/mempool.c            | 27 ++++++++++++++++++++++++---
> >  2 files changed, 26 insertions(+), 3 deletions(-)
> >
> > diff --git a/include/linux/mempool.h b/include/linux/mempool.h
> > index 4aae6c06c5f2..822adf1e7567 100644
> > --- a/include/linux/mempool.h
> > +++ b/include/linux/mempool.h
> > @@ -18,6 +18,7 @@ typedef struct mempool_s {
> >       int min_nr;             /* nr of elements at *elements */
> >       int curr_nr;            /* Current nr of elements at *elements */
> >       void **elements;
> > +     bool use_prealloc_only; /* Use only preallocated elements */
>
> This increases the struct size from 56 to 64 bytes (64 bit arch).
> mempool_t is embedded in lots of other larger structs, and this may
> result in some unwanted bloat.
>
> Is there a way to achieve the same thing without adding a new bool to
> the mempool struct?

We could split out the part of mempool_alloc that uses preallocated
elements without what waiting part and expose it in another API
function named something like mempool_alloc_preallocated. Would that
be better?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZft0Nkc2RrKofi-0a0Yq9gX0Fw5Z%2BubBfQy%2BdVYbWuPuQ%40mail.=
gmail.com.
