Return-Path: <kasan-dev+bncBDQ27FVWWUFRBVE547XQKGQEBWTQY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id BB396123FF3
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 08:01:41 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id f2sf618680plr.21
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 23:01:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576652500; cv=pass;
        d=google.com; s=arc-20160816;
        b=EIKhPkJ0QQqbXrHuWAbQpn98uHpvB/6/0zGeAiIKO46LcGOBU4n3N1A8KtVxcG+ahw
         52ciCl5ZgEVSieFFDOgf86IHLUV0YERrQ9JcYvOB4KtEnUXyiX4bW0vhxiEUNnWfKpos
         scEkwC85VYsMVzh0zgbXMVwPmrbYUvQ4EaQ9uAM6ov8P8xNxpNq9Zd6cbT3GypL10tI9
         X0gvAQlWmp3Q/pkg7q78+V0mnJy4luInU3atQsVSVa6422cz7cCnsCfxjlJatOzK2eky
         GDURgyhs+5npyMwttSiexKc/h9STPGGtffbIigaJU7I3EWSldz3OL8gAP+/BEYTtpZtr
         ldmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=cACAXIntGqu1emSB+Cxy7OuVGOSqDrUlhr/1odmcj20=;
        b=zZjEgqAR5VuYSVcIAAcN24orIItvqxgHNi6NJp0r6kODKFCZFGWSTeeZwq0IUyfZAb
         BeyqkEwf2+xJe8Ha13W4dziIT1D1g7MCz0eEEUaDNvh6gpmKKDS+9wz1xdN8pGUv2f2N
         vhmsMpVPVntzO0OJOzMLF2HTGsakcgJh5thr4TIfX3LTxQ7+ZyLfxy/Yjbq/hPzB11fr
         H3lOCDyiC2q5iwVlXO7vNVWz16p9bEHB7cauatB5DZshWkMWYzuoBvzyhH85TPPgb8Sm
         CIlQ1WQWkFPNLKjsV+nTpD9ClLzcAWO4x0tACh9NE012HkeOuoIOXnLiXkUDVhtDR8F2
         g1mQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HJ57PQOL;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cACAXIntGqu1emSB+Cxy7OuVGOSqDrUlhr/1odmcj20=;
        b=IkFR4QrfM7BRR7GxZqfv1Uo+PzFd+1S8u4Yq2akhO/oR93s0TWVyj9TH1x7bymJoCc
         ZH7mx3iy3du53SZ5OUOd1K55ig7x5G6pjLb94WpEjEoDzB0FOt9NQggMN+Q7d+gvWDfO
         Blt0MpWak4jfnrHx64mMr+B6CX55jq11xkvpeeiepA8SzsqdwdJnOstNz7Xjc4uqEZ0k
         edWK5wme3aRVJp1Ptvkh7yFfG4TJX8vRTYdL6g20bjWDjjtK4Fg0rcBdvIpKexy7m3UH
         ed8jBYC6+bUbcNz+ur3VSJ9dK9cmvbv8la1IFvnVcLFt1iSJybtckZz/y07z85U67g64
         RbYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cACAXIntGqu1emSB+Cxy7OuVGOSqDrUlhr/1odmcj20=;
        b=ZuPmMvxzuBRXGqR43ho7aHEGjbMQQJ2fO7s5hl/9v02w4wIUpwuKjo5S58Tbfnebzl
         WBLWb3gXZBtsX8kknTwdP7lELiOl06gqNaiV5nAHlGw3NZYuPQxYqoAL4T8xMMrGlZSL
         W/FkxO0+cKkFYqt/x1s23xaQb5wSX3eHOqnDcc6bGTV87nGjrQFtU8W+vAZYpyOnw48m
         rPYyAF42TMDVh6KD5hh5oupQTGo+PhPCNb16KKBKudWnlfvptZjIBLZleUGpbvk//osL
         6epYAl+CYS+N3/ksHQfpyWW+VAmi3Jzt3ngFHKvRk6/7y/mZmoPKNCvbttO/A3uuZg6b
         Oi/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVpYDpbMq5VS3YIL/oNDC6SYlzT3luZ7JROY0+dpDeGsxIZUtNF
	CTSGyl6XeMhZHJvah8i2wlU=
X-Google-Smtp-Source: APXvYqz0tKCYju2gUsaDyWAsPOzez6JHn9hNF4hgqBw3oWg2kUeHGpUXodaVqx6WVGsTKwg3WQHkUQ==
X-Received: by 2002:a17:90a:fa95:: with SMTP id cu21mr985950pjb.129.1576652500422;
        Tue, 17 Dec 2019 23:01:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:724a:: with SMTP id c10ls365000pll.1.gmail; Tue, 17
 Dec 2019 23:01:40 -0800 (PST)
X-Received: by 2002:a17:90a:8584:: with SMTP id m4mr967126pjn.123.1576652500025;
        Tue, 17 Dec 2019 23:01:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576652500; cv=none;
        d=google.com; s=arc-20160816;
        b=ibk0kPrqP0jm5ieTnvv7qvaS9SxDddCvnNwFFOGM8au8oK9Jk8/44QDU792ZLqIbJu
         NCsSZLivsUUytLPXvUiUyhL9AxlGvqgenuuysHmDn/ZkDAFK1KOJnAR0sXr7qENXXF6h
         S0cBun416OvFX+A8dAPvjVJrbXnUAVcuRvOy3dz/3FJwoVEV0JPQY6O1+FORXUVuMFvb
         U7U9n+p8/mgpB37GxprKrTeiivFQKtfRO3mRuz9yFM5N0jYZ0UfiyJWHlIkHE73JdUWK
         kaUOlb8CQqXTPH7V9ruY0Av0AIbcFvetBT1r2/Coh/orEsZBiBYD8b0Pj09euPtIuyTQ
         dswg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=BZCWkhOFV3yf2yR16aoRfXzQzGQ6DZmCFUiKpUKgtKg=;
        b=bkbWIP0lQPAPRhgDBah1zJk94szxEmVjrVZdCzHEEY66SBnBSc5g3pOa4zRRfPvb+b
         kRnlC6aChJ5FjCDx7ae1ZtVfmUGfzDNH2SdSvK2Wl6C4TxTvbNradeykU6B6ZLG3Pqd5
         lNHnGQng2YT1E3em83V/+xN4jOsQYphYkbLDKF7IEiIXrGgFyWpOT1XW63KQIcKMJM/E
         00TzPM4PEfArvQkWVIrrUQ2klX9i5lAKaBszYVXeOxiPhdUtJ4HsrcBI6YAYjt/jVTrj
         H3hPggk3CFLaVjaGWLTm/b8ZhkaV/MSxgUuhRrd2EtSQ8NX/5xFF46weAEtgY7sTbKLf
         bUXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HJ57PQOL;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id d12si205875pjv.0.2019.12.17.23.01.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Dec 2019 23:01:39 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id 2so667044pfg.12
        for <kasan-dev@googlegroups.com>; Tue, 17 Dec 2019 23:01:39 -0800 (PST)
X-Received: by 2002:a63:3484:: with SMTP id b126mr1263334pga.17.1576652499643;
        Tue, 17 Dec 2019 23:01:39 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-a084-b324-40b3-453d.static.ipv6.internode.on.net. [2001:44b8:1113:6700:a084:b324:40b3:453d])
        by smtp.gmail.com with ESMTPSA id i127sm1608577pfc.55.2019.12.17.23.01.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Dec 2019 23:01:38 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Jordan Niethe <jniethe5@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, christophe.leroy@c-s.fr, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com, Michael Ellerman <mpe@ellerman.id.au>
Subject: Re: [PATCH v3 3/3] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <CACzsE9q1iLgoMLzVy0AYeRvWbj=kY-Ry52y84PGtWw3YXXFipA@mail.gmail.com>
References: <20191212151656.26151-1-dja@axtens.net> <20191212151656.26151-4-dja@axtens.net> <CACzsE9q1iLgoMLzVy0AYeRvWbj=kY-Ry52y84PGtWw3YXXFipA@mail.gmail.com>
Date: Wed, 18 Dec 2019 18:01:34 +1100
Message-ID: <87y2vat8vl.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=HJ57PQOL;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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


>>    [For those not immersed in ppc64, in real mode, the top nibble or 2 b=
its
>>    (depending on radix/hash mmu) of the address is ignored. The linear
>>    mapping is placed at 0xc000000000000000. This means that a pointer to
>>    part of the linear mapping will work both in real mode, where it will=
 be
>>    interpreted as a physical address of the form 0x000..., and out of re=
al
>>    mode, where it will go via the linear mapping.]
>>
>
> How does hash or radix mmu mode effect how many bits are ignored in real =
mode?

Bah, you're picking on details that I picked up from random
conversations in the office rather than from reading the spec! :P

The ISA suggests that real addresses space is limited to at most 64
bits. ISAv3, Book III s5.7:

| * Host real address space size is 2^m bytes, m <=3D 60;
|   see Note 1.
| * Guest real address space size is 2 m bytes, m <=3D 60;
|   see Notes 1 and 2.
...
| Notes:
| 1. The value of m is implementation-dependent (sub-
|    ject to the maximum given above). When used to
|    address storage or to represent a guest real
|    address, the high-order 60-m bits of the =E2=80=9C60-bit=E2=80=9D
|    real address must be zeros.
| 2. The hypervisor may assign a guest real address
|    space size for each partition that uses Radix Tree
|    translation. Accesses to guest real storage out-
|    side this range but still mappable by the second
|    level Radix Tree will cause an HISI or HDSI.
|    Accesses to storage outside the mappable range
|    will have boundedly undefined results.

However, it doesn't follow from that passage that the top 4 bits are
always ignored when translations are off ('real mode'): see for example
the discussion of the HRMOR in s 5.7.3 and s 5.7.3.1.=20

I think I got the 'top 2 bits on radix' thing from the discussion of
'quadrants' in arch/powerpc/include/asm/book3s/64/radix.h, which in turn
is discussed in s 5.7.5.1. Table 20 in particular is really helpful for
understanding it. But it's not especially relevant to what I'm actually
doing here.

I think to fully understand all of what's going on I would need to spend
some serious time with the entirety of s5.7, because there a lot of
quirks about how storage works! But I think for our purposes it suffices
to say:

  The kernel installs a linear mapping at effective address
  c000... onward. This is a one-to-one mapping with physical memory from
  0000... onward. Because of how memory accesses work on powerpc 64-bit
  Book3S, a kernel pointer in the linear map accesses the same memory
  both with translations on (accessing as an 'effective address'), and
  with translations off (accessing as a 'real address'). This works in
  both guests and the hypervisor. For more details, see s5.7 of Book III
  of version 3 of the ISA, in particular the Storage Control Overview,
  s5.7.3, and s5.7.5 - noting that this KASAN implementation currently
  only supports Radix.

Thanks for your attention to detail!

Regards,
Daniel



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87y2vat8vl.fsf%40dja-thinkpad.axtens.net.
