Return-Path: <kasan-dev+bncBDW2JDUY5AORBENOSGUQMGQETJNWHHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 137A17BEABC
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 21:40:03 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2790ded9f06sf3307200a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 12:40:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696880401; cv=pass;
        d=google.com; s=arc-20160816;
        b=uWkzSB6413/zoO5lvVEmyBKZDH0m0k8sp8umLfF/1sei/Z6XcKntcyxQSiTNtyJEio
         irWGamIKYBDI1zXMic29x87C6WAVnJoU7Tv2DBcOflbE65LqAYSiOFFwUjQsqAAkDJJH
         +U3VzT+AZpyfVzjYCXmA+c+NBdKGEDuHK/1huZkZ4nG7bsnPhuU5f9T8rt4UQ4JwPSFw
         Q/ciD70XaKc9f4cnKOWDzBHYjnqfFnMBwN/QWPmA+5vznZ15gwgFPpGrcJMd3FCdovyX
         G5neBR1uBpOxVr1jgazUZJWHI6cmZolnrayqHm4bm67sJBlc8iRD6gKyRFErL46Mur+B
         cmcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Qf78Xw7M9jKab46euCU9Wt/ad8hCHEIUfW6A30lyHxo=;
        fh=MST/rnOhcICqtxKZHjUiLEuOFwmbYRRPAmdJv5I9JQY=;
        b=FE3q4Hvt85JZCOBFlKHnIDWblkPXStVavYlGpNWOmsOzbuJNk7EaQOACekmFgzA6dB
         He9QSmmJufr16yZZLOwvEeYBpH8UE9YDW9oKRPGjeDVE57ygNkvd+72Ik4MbAgtj5xRu
         xDZlXzgC9j9s5tKFqPpITFqlrOXkSTLJ2eahpbNKHboxZcjgIFiXmEObFrTfxs9xKsia
         czFstlUHfEaD8Qs+zk2GMNpoBg2VxZWq76Ona4NFLyuC9i0vvEjBCWnZ25tnJNHQbWws
         Os0lKYLft37gCHfIUqlKYx6hJD4+qrCWwW7Kts/lCUN6zMic23lyTYcW03YWfUrvBf+u
         c6VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Cs04MWQ/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696880401; x=1697485201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Qf78Xw7M9jKab46euCU9Wt/ad8hCHEIUfW6A30lyHxo=;
        b=pP+YGXtVGpGVTtKjiCZhnXY05HLcPWaMTgZdN/EkhoYO1GuVzITATZV7d1NthjCGr7
         Bwx96R+l4hxtCs62wcuF4gk2LzfL1twjqLc4fD4/qfu6PaqWinvmWcq8aRIrDvh/EkzW
         6wivFOX+mogKzD1alR+5jXnpddReSylmH08rzb7g1KYE3rnFtJWaJkr99o3vbxVNGbwu
         BGs1SEA4MuKAE6FS0HDkmNHb6LRa2870m3uvWuGyST75PHhMZnDvrHHs4GBjJOsWyX68
         CInenkS6jIAltqLHbypsqn8k1DPAiLxUIJt50aBLnmy8yzqeSwzhPSatxotCKG9Kzjb1
         9Hkg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1696880401; x=1697485201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Qf78Xw7M9jKab46euCU9Wt/ad8hCHEIUfW6A30lyHxo=;
        b=PG9Revu8lQN0z0U0D2nbbZ1MtYMh2i62p+JYTV5st4Slt9/5TsBRPpqjavy97pO3zs
         hupuQHAJhJturxRGxg9VV74hRUK0QjEv8ZE0vCUg3yt8KDhyYsnUDjZxZPw9wHiJVOZU
         0HHPNmAnp3gVOH1eGqXRQrEzTXuKPn5JYC42aYkOyMpUtcY3+Qec9efeR9HnTY/sKzFA
         aHSstzaukzodsXtPHu+oRZFZ+3FdcKXgZ3J9W3yh+VC8aX98nP/33ajs0v7QPq3KF/UX
         7NyMfEMBwKCp0UL1GuI+0ueIXhRKrYTje0n+3XUOoebNehkoQ3xlbqjiFTy4yyI+ky36
         oojQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696880401; x=1697485201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Qf78Xw7M9jKab46euCU9Wt/ad8hCHEIUfW6A30lyHxo=;
        b=KSg7LLStqfIHSTDaLHi/Bj72Cjp0W6jugKt9ONmfTEXtjjfqUdS09spXQqcoIIeeJD
         Ml6Q2PDaSURiSkXifFAl8nyFBff36vvxGSnQ19/EJllJiKRFvGphbeBPbhO+RAp+B6Q0
         DciqVW1+v3CnAmyKpGMu/UbKbnlC1D23rJc2j7KSAotW188EfRWFMY9WMM0/fJvzYlQe
         2XaMmwLS8YGXLLibf18qFCKX5pIj5NE7GEQuRuw01M00AymynETfQLCBmpFde0r6i9qj
         HQ0pGNHIF7NnweWCi8XnUpxZhKGo7sOCgOo7hVfhos4bpqCrFaRAKC5KLWQXbQHsJWo4
         funQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz3+PZe9xeYK6eYektNN+OBl+CQKiVSDpxwaBwfUy2ywjzKjWjb
	pisVy8kp1OFZfeQfh0wMalU=
X-Google-Smtp-Source: AGHT+IHoN/uMZePweJKRpJGm2BgJfV1bxMT8oDWcJlbXkQv5pnnI4AQqidLlYyimNfrAZMTdkvQeHw==
X-Received: by 2002:a17:90a:f414:b0:271:8195:8 with SMTP id ch20-20020a17090af41400b0027181950008mr12870113pjb.36.1696880401337;
        Mon, 09 Oct 2023 12:40:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:374a:b0:262:dc9e:41ca with SMTP id
 ne10-20020a17090b374a00b00262dc9e41cals2435499pjb.0.-pod-prod-07-us; Mon, 09
 Oct 2023 12:40:00 -0700 (PDT)
X-Received: by 2002:a17:90b:4f8b:b0:267:eeee:ab17 with SMTP id qe11-20020a17090b4f8b00b00267eeeeab17mr13219457pjb.45.1696880400283;
        Mon, 09 Oct 2023 12:40:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696880400; cv=none;
        d=google.com; s=arc-20160816;
        b=pClOebpw4mCyKAvqueisXhdHFaLI17dm+j2vcxQyMhmjIFsLWzfHP3/srjyun0hiXz
         cXROKcfsUtPTD4DhVLNsZqpEtyus0n/axCznGvriSzBlNsr2VVyb5ccQMRoSZxkij0nY
         gYKQgx8cA9uY8R7CCmxExJ2tzWi3Ik9b0zvVEcpAwhXvr575T0FXjRyINZ9nBcHXdLfR
         dcnmgDlBp4R2yYgEBrLCwnaSKE7qz+7meD97DaUlvJ1Pmu07WPyT/NBLMXz47qjHqRY4
         ErnhSC7qsD4uwi/tG2iPvHioWuwwWaSYhr91/0OdIF88YN6ksRkJCj5PKXKng4GyU36h
         D0wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uQ3ZfP4NZWf00Sp5FRs8A4GOic8A7MU965Tw6O82KGM=;
        fh=MST/rnOhcICqtxKZHjUiLEuOFwmbYRRPAmdJv5I9JQY=;
        b=eSLsmuzFVy6M/7W3wA74FWZLCeGsefvuPMIh0kRwNz8TgvE7DVuAZmjzAnU+qeAC9y
         XVSqEOKuOpoLYaXx0bsAljOFN74RxQRl8Siy0JxjjIsJ0kI4MR7dUK4B/kXFUPzHXm9s
         n98jVXophLcfmnECPwSmnVt0OzLcqpbCGYKVYj8thVf4Lf5FtRcpirADCLyuXYzWp+Gr
         BXjt535Yczvg6udyEnFZf4QE9EMlInQ8mY/Tb1MHbbZZEmYGlupjerhbQm45bUeSHJKy
         0TrA7ewFI2HMy2TQpSTovNQ+gJYatKqTfH3c9B7FvPpuU15tuTIXTk887iV97F36nNJ5
         QOrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Cs04MWQ/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oo1-xc34.google.com (mail-oo1-xc34.google.com. [2607:f8b0:4864:20::c34])
        by gmr-mx.google.com with ESMTPS id oe12-20020a17090b394c00b00271a1895140si477554pjb.0.2023.10.09.12.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 12:40:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c34 as permitted sender) client-ip=2607:f8b0:4864:20::c34;
Received: by mail-oo1-xc34.google.com with SMTP id 006d021491bc7-57bbb38d5d4so2805708eaf.2
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 12:40:00 -0700 (PDT)
X-Received: by 2002:a05:6358:591c:b0:143:7d73:6e63 with SMTP id
 g28-20020a056358591c00b001437d736e63mr18655566rwf.2.1696880399492; Mon, 09
 Oct 2023 12:39:59 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <CA+fCnZckOM0ycja3-=08=B3jwoWrYgn1w91eT=b6no9EN0UWLw@mail.gmail.com>
 <CANpmjNNoBuNCf5+ETLOgMbjjYFT0ssfb4yyYL21XRrOgMc_mfg@mail.gmail.com>
In-Reply-To: <CANpmjNNoBuNCf5+ETLOgMbjjYFT0ssfb4yyYL21XRrOgMc_mfg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 9 Oct 2023 21:39:47 +0200
Message-ID: <CA+fCnZd3HdXyx3dS0-3TQMDFbm1=qFQK7-2drHE1LE1ON=Ao8w@mail.gmail.com>
Subject: Re: [PATCH v2 00/19] stackdepot: allow evicting stack traces
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Cs04MWQ/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c34
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

On Mon, Oct 9, 2023 at 2:35=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> > Hi Marco and Alex,
> >
> > Could you PTAL at the not-yet-reviewed patches in this series when you
> > get a chance?
>
> There'll be a v3 with a few smaller still-pending fixes, right? I
> think I looked at it a while back and the rest that I didn't comment
> on looked fine, just waiting for v3.
>
> Feel free to send a v3 by end of week. I'll try to have another look
> today/tomorrow just in case I missed something, but if there are no
> more comments please send v3 later in the week.

Yes, definitely, there will be v3. I just wanted to collect more
feedback before spamming the list again.

I will send v3 that addresses all the issues and new Alexander's
comments (thanks!) next week (travelling for a conference right now).

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZd3HdXyx3dS0-3TQMDFbm1%3DqFQK7-2drHE1LE1ON%3DAo8w%40mail.=
gmail.com.
