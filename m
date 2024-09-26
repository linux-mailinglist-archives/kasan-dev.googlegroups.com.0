Return-Path: <kasan-dev+bncBCAJFDXE4QGBBLFE2W3QMGQEHOSUUAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id A343798737F
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 14:23:13 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5365aa7a1easf566759e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 05:23:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727353390; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kh8sQr4HTVRKn0x0Nj4vb3FBv4rVCKNG8eTF3fSZwMV6tvh9xUhxTI7aR9Gw6gB2J5
         u8eNHkzZWUqSOi4x5cDWBdVJQBDFCKOgWCxk78uiO03iJYT9Y8ozsXNLwcc+6QyxnE41
         jO1BVuERqVMPXHqnwtQXCKMg39GaOQDUIuoTmPyWQ3yfulTh3vhB92Pwot/DknlWpzQ+
         vaLhLvI5BI/8Dxv6fPQa2KEcI82cHdHxQsLdfxj8ONVkCT04lkKNczm4rVCTOBT3L9gU
         A4zUvensQiC3SdzCrdN6S+0p4Dtg4pcTntCTy/nGew5kAI1zu3nIb4VTQba1d9btNEbj
         Pyrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=osBXBWi0TDg9F7EQ+Ee4Eo174Hp5Dd1xug8lQB0pNWA=;
        fh=vk7UZ8Iy3Nx/6mDIKJCwM4vpRe8ykCmGVaI0LLjb0s8=;
        b=OoeZ/26Q5Nj9Y5mzVsgA3ETuoJFPyYo8WvAkv1rMNMaamy/F6SS27Ly8USf0+QDC2e
         Yg9BUq7FnHGTCBXmJx4wwXvjKR0QgMckT9c9qYWUqGOGjKotgALOJAKPhtWRwVLwbdmU
         Y8CWSwiyIC51SFUeuFKjIKaG9oR8TpP+cJOySYO6DgVsDILrlFQ/1ppQK7RlC5BpH/u3
         jYlXOMV0J4fu+Bq1Q9aSJIbSEiVfU4mbO8rKL76WOB9610EIJVP5HtAZbEuW9ALSx2M4
         WscY5rlOWs7rLE5Z8dNFbox4fmTIWJCfq+NzNpP+WlF5PyOliok6ygyKmj8QfHatw0v4
         4PZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aLvs41+K;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727353390; x=1727958190; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=osBXBWi0TDg9F7EQ+Ee4Eo174Hp5Dd1xug8lQB0pNWA=;
        b=Cj53h9MQB9GDd4RXugZsmrKzLmE8QBMVxM9VQrwWl2G4zyzy7MBu3ozbz8rv4pbaxZ
         lpL2TxinxyJ8fNy3Ie+kxo3oz+TayLBixWZs8rteKDw3mnQUSA/BmojgghFngDd/1qbN
         Fc5qwbyDKssPQMQuRxlkDqmVZzUbEyZ2i5DzWzqp9bHtqx4eXxOizWMwgzpLfJmzAIfh
         ahslK7XHiT64OSQfCcWKrUV6qfWsNk9A/ZIKFZyU+uRzQ8QsF/ib3oDzmw+SY4bs9cfC
         uEdKpVo871g/JRzF3pAWJ929cpivxkI5oORYJ/Hfs6IaOZiZNmCjh4aesYZQRBVxWTCf
         nF7A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727353390; x=1727958190; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=osBXBWi0TDg9F7EQ+Ee4Eo174Hp5Dd1xug8lQB0pNWA=;
        b=SCwVTxOcUzn5myZzQuoD2/Qv+HgE4WmCxv5lDZIhznnrN0K51pTre2JtOvIwRXZpWi
         5gQF3BkQiJBToYdVEZgHlcp54En465eXpDAGZO9X0kf+OFYpkuv6dZvySrswm+hq4Q8R
         lsLTvM9+UVIp+V9yPtrgn2YHmHOtwggtsljP1Ti0qAwcMoqZ5yThfsfa86tAKIxTZx7S
         kQWy37DnXD5tZh8g6K3r8GHdkD7Omx+WFvrTGa0Msp0uCVq/oqt1S+oIls5zd5lVbU6S
         GKdyhxLrwo7Jsz5UhUDWCGn3X/On0J4gEdfjvunQ729UmZf2NN1564F270ssgTPNew3r
         +VwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727353390; x=1727958190;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=osBXBWi0TDg9F7EQ+Ee4Eo174Hp5Dd1xug8lQB0pNWA=;
        b=ubxmULeFYHARYIyXkB07+KFrNSEym7eRbmcuK6RWVxp6su4Vi6DGB6ZS4GJft84A5Y
         /6CfTQlVHJunULiVsEE3zwqSdTDcHFtnv143JCyX+ww1qojeMMqq9pGomHGznKu+Vr1h
         xHS7llEsYdYZsLvZSz+uM/v6+FfO5X7ZZa45bDXrlrQiUfDkT27B9herLE4Lm9iV42JW
         DVjAC7i9W4xfUfjFj3jQOlX3912WM/NSdedO2fOFFonxXeClhc7Ci0U/TTHACVCW/r/H
         wMz1g3NZ2Vh/cZ7QNMs6225wy0W09EnkUyMQfJoXP78PtXuyWJUSLziDFizRnGsjN820
         uxKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXU/dvYVZWRVhKTUqJbkZwGypjC7CeLEFq+Byq29/kMr7WqKWAauCJb8xiZQcy8/LgQttmR0A==@lfdr.de
X-Gm-Message-State: AOJu0YzvcBb4qA60CInYIgomQEBnloiq581AXhcV0JnMoYd6yogkjOoO
	fO4M/tuqdtdxKAuGF+EyQKX6EimjKNv6dR5XKIcyIAEfBN07kNA0
X-Google-Smtp-Source: AGHT+IE3CF+JRTtpQZseBMaKhBLKL7qFVj39+kf/szB8vXYVcl8dGkiajgfE/14c6OiqaFKEwj1SWg==
X-Received: by 2002:a05:6512:31ce:b0:52c:dc56:ce62 with SMTP id 2adb3069b0e04-53896be81acmr1068744e87.12.1727353388869;
        Thu, 26 Sep 2024 05:23:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1044:b0:52f:c72f:ddd with SMTP id
 2adb3069b0e04-53896c77817ls289309e87.0.-pod-prod-00-eu; Thu, 26 Sep 2024
 05:23:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVHdm20+eFiRkXFj6gwnty2ObMQXeAr8QlMZqxIwKMFozTuebOY1NQ3n5mWb5X4ayFIZzvXIU/ol14=@googlegroups.com
X-Received: by 2002:a05:6512:3095:b0:52b:faa1:7c74 with SMTP id 2adb3069b0e04-53896bde54dmr962600e87.5.1727353386846;
        Thu, 26 Sep 2024 05:23:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727353386; cv=none;
        d=google.com; s=arc-20240605;
        b=CeTrtmH5biov5Pu927bNl2SFMoBcJo3aLvdyD12HGM/hRZRLhMSaiM0Fyib0VbiQEf
         sXe2DFUGLN/DlsyQYxQkOZ6vcQwSjf608co6XhLkh3Fr7xzLCNcLSXFzYq0N7HCvt88j
         QRObH6r+kFpAHFXvIx4RRf0W3KCt4llZngAdKjBg7sJLNOCMg4Z0/r7FmXR/PbimFsWE
         U2vGMoU/2ANC7guUkYsjE5PowVYy//772/uO5u9sEcEN95OLu4hLkfLjftVgqxRuIpmt
         Vq1Y+QvcRGLknDblABH8YILafapCYFRks6sKt3PNS5nSqowddrReUL4+/APO2uXwpDt/
         qTnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OOtAdGSLmtU0Tl9JOnUIzkV8dLA7+CwP/jLQK5eAiLU=;
        fh=nz3vx3zio2TIW2761dk+aN5uvAGP11L8Jg3IvMSxBp4=;
        b=FTJGftoBsVO5SpWZP7qCMtMZkbvD/lHwMTn/NSywrQBW2WV5QVmsZnN0cY9JipGylj
         KCBpjkrLe6DDMlOWKoMuJTnxnMKIirCs69d0nchiMjay8p1eBJJ4LM8KycBOxqLghYsl
         P4RKM7OD0vey+NjszFaR+Sok7m0Txn2tbqQX4YHNhihY8J9ZL9gvr8ffXneYcb7FW+3Q
         RvqHH+v4wWuusOwown0mVhIhUT+NUVMR21oDLuZrjLTGK9aLAeTFQvHJM+y2u2BY0LwB
         R/UAIQikcZQ6qkCjHj7JjHFnk1F6ieWm7AQ9RRzRLKUKPBW2uCMAW9irgJyXQn35MD5S
         kIhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aLvs41+K;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-537a8567575si116424e87.0.2024.09.26.05.23.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Sep 2024 05:23:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id 4fb4d7f45d1cf-5c40942358eso1686425a12.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2024 05:23:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWOSY07UXMWk4aHKjqX5GPTRFIjfrJp0fggkM93cpG3XDi0Z+mgiQ2jzATfKQjkCgj4qXTHjQXpzks=@googlegroups.com
X-Received: by 2002:a05:6402:40d2:b0:5c7:2209:dedb with SMTP id
 4fb4d7f45d1cf-5c8777b59c1mr3107804a12.8.1727353385705; Thu, 26 Sep 2024
 05:23:05 -0700 (PDT)
MIME-Version: 1.0
References: <20240925134732.24431-1-ahuang12@lenovo.com> <20240925134706.2a0c2717a41a338d938581ff@linux-foundation.org>
In-Reply-To: <20240925134706.2a0c2717a41a338d938581ff@linux-foundation.org>
From: Huang Adrian <adrianhuang0701@gmail.com>
Date: Thu, 26 Sep 2024 20:22:54 +0800
Message-ID: <CAHKZfL0D6UXvhuiq_GQgCwdKZAQ7CEkajJPpZJ40_e+ZfvHvcw@mail.gmail.com>
Subject: Re: [PATCH 1/1] kasan, vmalloc: avoid lock contention when
 depopulating vmalloc
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Uladzislau Rezki <urezki@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Adrian Huang <ahuang12@lenovo.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: AdrianHuang0701@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aLvs41+K;       spf=pass
 (google.com: domain of adrianhuang0701@gmail.com designates
 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Sep 26, 2024 at 4:47=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Wed, 25 Sep 2024 21:47:32 +0800 Adrian Huang <adrianhuang0701@gmail.co=
m> wrote:
>
> >
> > ...
> >
> > From: Adrian Huang <ahuang12@lenovo.com>
> > After re-visiting code path about setting the kasan ptep (pte pointer),
> > it's unlikely that a kasan ptep is set and cleared simultaneously by
> > different CPUs. So, use ptep_get_and_clear() to get rid of the spinlock
> > operation.
>
> "unlikely" isn't particularly comforting.  We'd prefer to never corrupt
> pte's!
>
> I'm suspecting we need a more thorough solution here.
>
> btw, for a lame fix, did you try moving the spin_lock() into
> kasan_release_vmalloc(), around the apply_to_existing_page_range()
> call?  That would at least reduce locking frequency a lot.  Some
> mitigation might be needed to avoid excessive hold times.

I did try it before. That didn't help. In this case, each iteration in
kasan_release_vmalloc_node() only needs to clear one pte. However,
vn->purge_list is the long list under the heavy load: 128 cores (128
vmap_nodes) execute kasan_release_vmalloc_node() to clear the corresponding
pte(s) while other cores allocate vmalloc space (populate the page table
of the vmalloc address) and populate vmalloc shadow page table. Lots of
cores contend init_mm.page_table_lock.

For a lame fix, adding cond_resched() in the loop of
kasan_release_vmalloc_node() is an option.

Any suggestions and comments about this issue?

Thanks.

-- Adrian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHKZfL0D6UXvhuiq_GQgCwdKZAQ7CEkajJPpZJ40_e%2BZfvHvcw%40mail.gmai=
l.com.
