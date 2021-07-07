Return-Path: <kasan-dev+bncBDF6JCH67IBBBIHYS6DQMGQEQGT5TLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E53433BF013
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Jul 2021 21:10:24 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id z1-20020a195e410000b0290229c07c3305sf1612656lfi.11
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jul 2021 12:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625685024; cv=pass;
        d=google.com; s=arc-20160816;
        b=PRkHfuQij2UNLacJdTOmsI08+grf6ck3vQu9DILjvIAVYzmzxg+plCoA9RvTDHNXHF
         AuYsMu/cCQmbQHbNfV33CLZ6s42Uk2lxJx76SpyH0PpGrq+DK9WXIPkNecKVj3rd25Fp
         8G+alEKK6ZAwpcSHi5/cmlNf7IVRlUvbvJH8rfvu6/Y9LcWLcro7ujYOjZ0JCSJSyxxX
         vBW+PePv+J9dl/a3Yke2c43xt6XfZWIV/bjcuei75KRd+rM16xvM9BHFSvAtrLIPDZfP
         xuflCJUOTcchqGVKMZ2V1i1oaTPvuKHMKIcmSKW0BPtPAotEG95esDFwnFNtM1PI/1P/
         cqRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=3e6n+yNcfrEwkASdslqKHJghmUNL5YrUXzcepI6EIJo=;
        b=OUWYBLg7TLh8rFChr94YodWlbI+a4vS8wtChlVMxpj0UlEUng5yY/mz6uARxvYD0L1
         kaIzeSpXTEuzzA7Kiq+9ZOz6XD54dYkgVVMZMhEO/P7s+nB9PoPeHy0JXC2QRDN2uZJs
         +SAt+BNjHsqY+je7JwzrKh01yM/ZqcGdu5DFF6gdXl1yEnJsMFQ+kKAVaRToCAfJYZAj
         /QIop9rRKEvdeOaWo2+fkC8pjqC626bCXtRt864Nke+DlOvfI9JPJItfo7eTJy7IB15B
         wsepSukRkTX7XGe12ZCJF3T0nG04fQrPpgxdH1eMUNdIXwb0B2BJ6uK02CjhQPlIkBiw
         eAGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QWWOKdKN;
       spf=pass (google.com: domain of ameyicelestine@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ameyicelestine@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3e6n+yNcfrEwkASdslqKHJghmUNL5YrUXzcepI6EIJo=;
        b=auz0Atb/vcfVq9pn4gB8+I4hKGfjQRUxeyaGxO9PfDbZTRE2pWwDd5HUrWJgoC6HvC
         8krmc5Au7ZS+bcgUca92CiiO7aG1vy5wp6QPcYoleO4T7Zy7s4CXxAC44nHmpJ76N0Mw
         xt2TuscNbku+Dw4V8r0nWYnFou9x7eLll2Y3U1D8pRCUBaGZGhUuF+aoTgguljt1cAmm
         i8Q3UNHVkWXUHKhe1JcKdqyaVQruD/Z9nmUhIFA7Ub7yRVdjxMB0xguFDCiU4jVc04ob
         1IWqXL5Gsty0EpOKMVSWIE3h50LluG/SbnUmkAuGL5UmRCVJc8/uHKcN+7MZTX2tJUbQ
         N6vw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3e6n+yNcfrEwkASdslqKHJghmUNL5YrUXzcepI6EIJo=;
        b=IUAvJ0uOkdvuqBsN6Z4ZkmlIe+uEWtY5aZJTVfP0D8OFCoX2zXZpelNkpnK3NTqGUq
         FdHD7udvxsHphjDEqrdMkmpso/l0eGMZf9/m9D0+iaIoSNRSLEsplJWN2VEYYtZn+Ao2
         r822pZ0tEfjAdahoQWYJjgmJTmJJcIvO1TPUkaweYFvz0QtvcS4V9FRFEIvyKfmdgLXi
         24TvNyPBitd2Y/mpO4XVYZ88Isht+INNi1ZAHkOuIoiLD4095P4Ms3qL5RUSczpoPseI
         hudntG3O893y/rnUa/4fPs9S0vr5iF76l0y6bQIjqBns1G6vE68FCz1pBKdEjXIX9FaH
         rJkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3e6n+yNcfrEwkASdslqKHJghmUNL5YrUXzcepI6EIJo=;
        b=Sn6lB9cgn6VUpX47e1bLeyGwNoPzxXs8yRGzIuXP7pAVnnB2xJp1ht/7h5C5Rhx//K
         h01ti7d+BcCZ3oGvfdeDyqK0xspLJyfpEzmlvaj9NqAFwEVoRy+ocSsP3JOtbZ1RWrjQ
         y2B6NZA3nL7I/bR4FoPe9eN3CFAsxgeEqDZJm7WE3+VejaOGJjXXH1d/WEOYsQ+jvGjC
         ro57wg9z3CA4br/m+I+rCcKRE/JgUuoQi+XrFb8O3at7ZswqbLx1CDzWv2NAbngR9sen
         yCfmmNalsNctpDcH7QqXLtO7hXqC82nEkjVu1jKiNXbPF1baA70ryQmjv/jiX/+Cd1m7
         iqaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532FJCTrJEjBPhTSGD5ixrLGmjmTXXI8jA2sPqJORI1kgvusjyxZ
	Fg6czjTUrpARWVCPYiVWkNo=
X-Google-Smtp-Source: ABdhPJx7lItgI3h1kluDZYFCL9ltx4YLfYEpxMBNGNsjPptQeuamLs+OQDRRwh9jN/oVpV18KkV4jw==
X-Received: by 2002:a19:6f49:: with SMTP id n9mr17447538lfk.459.1625685024486;
        Wed, 07 Jul 2021 12:10:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1799:: with SMTP id bn25ls4477945ljb.3.gmail; Wed,
 07 Jul 2021 12:10:23 -0700 (PDT)
X-Received: by 2002:a2e:8613:: with SMTP id a19mr20661710lji.410.1625685023379;
        Wed, 07 Jul 2021 12:10:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625685023; cv=none;
        d=google.com; s=arc-20160816;
        b=sgeykd7svfI+zEGNV/TgbMkxinci2EIdwebvTFn/K0t5e232JDX7M3udxjC3E8uvxQ
         kx5WAZRl17SPyroHYyyzcuxaeas8H3hPh4uNF2JhjN7hiNBk12FmOrHIYGVlI8gs5cMW
         rVUUoMPc5JJeL0dJGShD/qz/GjJzL0rLFV/r6zkzwb4ZiBK0XtAts4ZczFqJye3kdt9o
         MyryjHV1neU4xiWAe5Q4vdn8Rx4OigBE0a/IO6ZbnBoaKrkD8CK24a3AmXZEw77F5Kn0
         x2+lS8InbkPHypNOwjoJp8aYbfrXBvGkUllKr81tNpb98vtfy6vp+WkCK4cUnmOuI83N
         L7EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=4xJt5fBKH9coVs4G118oSCNpXg1LcVS2cApUTRvl0UI=;
        b=eK+ri2gZ3HGM6saKr5z0vUARbDDUVKV90I2ExViplt+xTbhIRPPUeuEWJuPPgnsrde
         HvVR9OUx4K7nGe/zKYMAZ9PE6/KmHdTG3wVuxq7TjvpOx5rii46tKwD11AVifDN6FxH0
         VRowzCj1clXIFCIPbaf9IHWIYy/Akmy1PLDETQCPKrVJECCdwTzVk/Bdv99BsvGFfksd
         SLxtFXrnYmPpZWduSRyTO64d2R+rqQp5B60ewsw68QscgO54TrJQos7W1gsCiMrRp8Pz
         4SvsetaM5AZI2mJORLM258ZukCWwm3/3dyYzuXpvLzPS/+CGEaLRY9NZOVZQw53H16h/
         vNZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=QWWOKdKN;
       spf=pass (google.com: domain of ameyicelestine@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ameyicelestine@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id u17si166737ljg.6.2021.07.07.12.10.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Jul 2021 12:10:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of ameyicelestine@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id v1so4842076edt.6
        for <kasan-dev@googlegroups.com>; Wed, 07 Jul 2021 12:10:23 -0700 (PDT)
X-Received: by 2002:a05:6402:193:: with SMTP id r19mr5237313edv.104.1625685022780;
 Wed, 07 Jul 2021 12:10:22 -0700 (PDT)
MIME-Version: 1.0
Reply-To: renderdonaldd@gmail.com
From: render donald <renderdonaldd@gmail.com>
Date: Wed, 7 Jul 2021 12:09:53 -0700
Message-ID: <CADbN5O2z+pvpE0hknRTFpzTB0aQGX93bfUfWB+7ixaL2_stXhg@mail.gmail.com>
Subject: HI
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000004cb12505c68d4a34"
X-Original-Sender: renderdonaldd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=QWWOKdKN;       spf=pass
 (google.com: domain of ameyicelestine@gmail.com designates
 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=ameyicelestine@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000004cb12505c68d4a34
Content-Type: text/plain; charset="UTF-8"

How are you doing today can we trust each other please kindly contact me i
have a good business proposal

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADbN5O2z%2BpvpE0hknRTFpzTB0aQGX93bfUfWB%2B7ixaL2_stXhg%40mail.gmail.com.

--0000000000004cb12505c68d4a34
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">How are you doing today can we trust each other please kin=
dly contact me i have a good business proposal</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CADbN5O2z%2BpvpE0hknRTFpzTB0aQGX93bfUfWB%2B7ixaL2_stXh=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CADbN5O2z%2BpvpE0hknRTFpzTB0aQGX93bfUfWB%2B7ixa=
L2_stXhg%40mail.gmail.com</a>.<br />

--0000000000004cb12505c68d4a34--
