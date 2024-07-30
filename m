Return-Path: <kasan-dev+bncBDW2JDUY5AORBFG4UO2QMGQE6WNTVFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D28C941367
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 15:43:50 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2ef23ec8dcesf48187951fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 06:43:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722347030; cv=pass;
        d=google.com; s=arc-20160816;
        b=RSqa3FZ9r7o8paWu2zwbs7n8PEEii7AzYgPkPMr08vClZWVmyWnyDzUI7itx9MeNXt
         mOISval99k7GbOALD1N3dQkR5zBtuAMbTxRrSc5+l04kG0wbZP5/vjMnFL93aauumB0Y
         WsRJApHxD4fWGL0HhvvGyZcMkHfUfmNNTSU0IJWXknZNUt/Rn0FJ4vNjHqf7sd3ok5Ay
         EX2IOlZ77+VWcMRw2Y0s4YNvctt0I7+SOWGy6BfNDSrMUKPn2keQscvb/WMfIc6yf3e4
         eZQpHrWun70SShBEiS2Cg6wWj0F8GYzWgtGdZvwPrtFpStSea0MS1wFIRQ8Gy3Tb98Ag
         5PJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=iGl4Q1bJ/qP1IJxdi5jP/jLkxhvgH9qAXB4MH6i2t10=;
        fh=96XZAhzmnqxkqFCzKbkqmoHDHY0TxcZBWnICGLdp1b8=;
        b=bd0urv4gASuBPBvFhtcskN5ybIQFRTV8YdpVQkwn019OwgEXvRyKV0bZ+JCXp6EJXQ
         3b9w6+MxX4D6e9sDZhXAyLhg5cbP6tqg6Ve/5MlZQOsQHWxzlWyeiYbQ4kha9f9mg4/G
         vJBSO63hKQMlC90xTgxU4Nh52pCe7UrDWW2rNuBrjFxxAneakPpST9y0k7PHVQ8UjDDm
         4nHeoX5W/5pL2jd0udLdfz04v3XLOBm9yvAbOOrQeItCEEGBP1rsDMLpyiuUXTUqdqpp
         9T+zL7FqJJdEAGSLWXcbP7cw4Kx6olWP3XHgSobv3dlNaervNOlXh9vDjMccA20Ja3z9
         ksEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=c5WKSV9a;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722347030; x=1722951830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iGl4Q1bJ/qP1IJxdi5jP/jLkxhvgH9qAXB4MH6i2t10=;
        b=VKx53SdVcRecUzUmcTU7svHYlz2+KS5RUAwrRn3c2ZPeAIxzqE8WEOHKz3INnOIxV/
         tI0yMlkkTgSTmu9LTDqFDKmvZxh+plXHRCtKdgT1NUWBlJdTmfPbk5mc8P8bi4Q78qsa
         9qdt4JQg2I/JH3VfynbhReSbimEcWg1+A1l3un6pmmHYTBGHfmdj4nnQwBcictUO9ToG
         qWnNO1C6bGUs395uurVhqRwKkk0PJtPoB9tuSag1LnAfdKAa3dqDj6QyX38w6MFTfran
         yx2UQ/2neGYG3huSBDIqjD1Gfn/UL51aawhSp2xhFzt7pxcmiarPSdz/WlZe+zCoFvIR
         N0Rg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722347030; x=1722951830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iGl4Q1bJ/qP1IJxdi5jP/jLkxhvgH9qAXB4MH6i2t10=;
        b=ZlanMqy+xtscjcXFwRm97q/a5CwB0XGGTg1nrZ8g6g0fkxb5UaC8cxYPdq9cQhN7fb
         1eX7qvOQm2WcAwnfyJa+BLZAMAbsr6ax4mvhYP0dAYgM9IR7tU62XWMxlF8cxaX5Yd0+
         zYlCaWd4rH/Mhak7UZmT0KDCeDFsLqJi52ldTF9xJMdsqJeJXD2P0sdbeFMls6N5TKm9
         nTa4QRMoD/uaMKRRlhh9ND5Abht9GSlNvWspKEG4JxXEFgp3Xfv0VXVCKZPf3gjLV+am
         Nzd71fSdUsHrYGNjk47WqXf/3HvQzwaoNY0ECLCl0C4rSZ1b6SAbuCuoxoYBvzr2qXha
         W9PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722347030; x=1722951830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iGl4Q1bJ/qP1IJxdi5jP/jLkxhvgH9qAXB4MH6i2t10=;
        b=lvCqYgN+0bPlU4320+D8LjFRflIY9DXwl1+iwy5dfh6vX5/QoEhqE20gPt5xhSuBjZ
         JnpeKuTu7sisgMTGUq9Daf3UvqopjeOS1zVffqhDVpjyvtuGCzS/ROO6h4F/D/3aSgHB
         sANTwGI2Gnn2EK2rrMAVVShovJaYcHTzVz1lyCRUx/SZosNlLhfVNGIbw0FfNokUdnwH
         VUqDnDa6Th8gD+Fy+HnArXUz38vHKrqL64ae882MWD8gYOrbRFCskCY/ElYA0n/QtXKz
         ZHlvRvXgBWcSsrIXi7K5yPxC/4PN4Fr3vX0bPlQ2IoZjydN36T7smP9qVgP3kSquyW6I
         WnmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWXuMr1lVGhdBwjfOP5oTO/oO+kUbmT9JsnPR/k0AeclMLI3BgkehvABmMvuRbRWaeV30ZtzBLf8Jl9RKICbbuG+0/sPixlLQ==
X-Gm-Message-State: AOJu0YwHQn5E525YRqiwI5uWz7y/JOtmD/fqepIcjhNOgOJ4EQafBChc
	mfKql1urAInFHSGjM37bkZObfkRDHaOAGYnajj1ebeLBPyggzbHL
X-Google-Smtp-Source: AGHT+IG7QurTkz3kkpjdk4RNv53vcbRieUobSiEM1ZaEMznx9O3m6SQnIcEaRMGhc/eD/CBbMRcloQ==
X-Received: by 2002:a2e:8006:0:b0:2ef:c281:54f7 with SMTP id 38308e7fff4ca-2f12ee233f2mr68200001fa.37.1722347029068;
        Tue, 30 Jul 2024 06:43:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:be1b:0:b0:2ef:1eb3:4748 with SMTP id 38308e7fff4ca-2f03a2cd04els16705021fa.0.-pod-prod-07-eu;
 Tue, 30 Jul 2024 06:43:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbZv3mY3D/JbhSkBs1KqVdk29EDYkBlGEOpx0ZZNvAM4UTVEsRmHLrp310y4PB8KmcFmeAReUzDvvV+wQ4xVAvuK+/UUdksR7lzQ==
X-Received: by 2002:a05:6512:3124:b0:52c:e10b:cb36 with SMTP id 2adb3069b0e04-5309b280a68mr5895500e87.33.1722347026865;
        Tue, 30 Jul 2024 06:43:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722347026; cv=none;
        d=google.com; s=arc-20160816;
        b=QrwK69qiKknohl8i9+z9gBnvm9IWsjmgBz6m80+WlZNEI+rh0NFDvqhH0LegEMCfsY
         ni/y4bD480NydENdGFPN5H6hH6330bm7NS2jQNuu5skzAmmSPixWdDRzOUjlTnkfswgp
         ADvW0FbWjrQVa/I8/8NM+Fcrc98KbFQ4mmXzwg21IWm9dEYm6nPGB9DQeHb1O5QWgr3+
         t9wNvvAV0QiWorFbv9p88tueOZzOcj9rWScjvRTcIiRNpdcR0epa52lz/y972ZY+v1y3
         vZIGiaD9YQFegT5eCFmYsxeXBgm1nE8z2p6bQTBZvGSuSmXA7+OB4TMHgUGPOjXn59lJ
         fGuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gtgxA2PssDFaogYfTQNLJ3b/Lh3FbXzi+L0/39/oBQ0=;
        fh=Qa2epLCRolvV6UQvj61npokra0WGly/UJe4qmTgoIi0=;
        b=e7qFGFjdI4zGU9hc04jYJKqm2TcMSGD8xMNtiXApQIv0k9WPCtEPhlNxyFPtcMRrnE
         XBWNo6JLxNfiU3lUVGdIs3gPLktoIj7oOj/72ZyswYwQF4gPmE8oisJw51X3WWeAI2fl
         l5N6hNbXHMRtejy8wY8SlGAAyzaDR/O03EO9J2wOWsdmdUMUztMwhjInfyFzxzSMsHe0
         3HBex+P0Sno1nZHp18rsOnX5jt6oJR2V6pahoMdJHqB7sXCOmrZNyAhnz8Omazc9XCNT
         9CKjvvmYP3cmusBz64nn/qkk6ksJKgPob9AVJMzUxhjf5TUZBXHFAYLFGTYocvfMMrnG
         knzA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=c5WKSV9a;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52fd5bee532si250373e87.13.2024.07.30.06.43.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 06:43:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-368557c9e93so2323964f8f.2
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 06:43:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXRajHBNyljhIRCPMCAeES6gZSORaWGgEAOJHxiPQNN7pRMwv1LWLS52w62afqbNK/cW0EY4ED/4Dwrb8O5C6164dLXPagIzhwElw==
X-Received: by 2002:a5d:59a8:0:b0:368:747c:5a05 with SMTP id
 ffacd0b85a97d-36b5cf2534emr8775942f8f.36.1722347025779; Tue, 30 Jul 2024
 06:43:45 -0700 (PDT)
MIME-Version: 1.0
References: <20240729022316.92219-1-andrey.konovalov@linux.dev>
 <baae33f5602d8bcd38b48cd6ea4617c8e17d8650.camel@sylv.io> <CA+fCnZcWvtnTrST3PrORdPwmo0m2rrE+S-hWD74ZU_4RD6mSPA@mail.gmail.com>
 <d4ed3fb2-0d59-4376-af12-de4cd2167b18@rowland.harvard.edu>
In-Reply-To: <d4ed3fb2-0d59-4376-af12-de4cd2167b18@rowland.harvard.edu>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 30 Jul 2024 15:43:34 +0200
Message-ID: <CA+fCnZebutAq7dfzutMhp-KO0vwM67PC7r4FRHPUcY1eg5rW3Q@mail.gmail.com>
Subject: Re: [PATCH] usb: gadget: dummy_hcd: execute hrtimer callback in
 softirq context
To: Alan Stern <stern@rowland.harvard.edu>
Cc: Marcello Sylvester Bauer <sylv@sylv.io>, andrey.konovalov@linux.dev, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, linux-usb@vger.kernel.org, 
	linux-kernel@vger.kernel.org, 
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com, 
	syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=c5WKSV9a;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Mon, Jul 29, 2024 at 8:01=E2=80=AFPM Alan Stern <stern@rowland.harvard.e=
du> wrote:
>
> > And I also found one more:
> >
> > Reported-by: syzbot+edd9fe0d3a65b14588d5@syzkaller.appspotmail.com
> > Closes: https://syzkaller.appspot.com/bug?extid=3Dedd9fe0d3a65b14588d5
>
> You need to be careful about claiming that this patch will fix those bug
> reports.  At least one of them (the last one above) still fails with the
> patch applied.  See:
>
> https://lore.kernel.org/linux-usb/ade15714-6aa3-4988-8b45-719fc9d74727@ro=
wland.harvard.edu/
>
> and the following response.

Ah, right, that one is something else, so let's not add those last
Reported-by/Closes.

However, that crash was bisected to the same guilty patch, so the
issue is somehow related. Even if we were to mark it as to be fixed
with the patch I sent, this wouldn't be critical: syzbot would just
rereport it, and with fresher stack traces.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZebutAq7dfzutMhp-KO0vwM67PC7r4FRHPUcY1eg5rW3Q%40mail.gmai=
l.com.
