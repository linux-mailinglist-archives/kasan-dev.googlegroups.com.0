Return-Path: <kasan-dev+bncBD44TTFEYYGRBVU4U73QKGQEZDJ256Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 31C971FC822
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 10:03:35 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id r5sf643002wrt.9
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 01:03:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592381015; cv=pass;
        d=google.com; s=arc-20160816;
        b=BVhWB9u0vSOXR6BUy2ZCWUcMzDzeW6eCD/2D/rBpq4eS2fpkn5O4v4sTOi+MdPKgfU
         H/GrEicGBpP13GiNTJPxMSHAvt1yko+lWzoEjQJR7rWEOJ4adaD5u1v7jFN2D+6nsMRx
         cAWaiAQt9aPymIxV9zVOUUS9yjPA87JugxsSOAoL4BMeR35ppHHXt2UBYGiqSmYLJgzm
         r1ZvsiNa0sULU3hYO6++8S07Malo6ioK1WhH2b9GR+/8QYlAZvpJaDlDbNeyd+38r8RZ
         MvJtwcPpvXAM17mRSgF0Ba6UZ/VP77J3JsMFqs73r2HEGZCNEjxF5B/ZB1hYxPN0TrCP
         mhcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=pQoMTPfhUogrvOoEYLRdXq4/5Omyx3r2EGywVbl2iJU=;
        b=gc/uXeBDue3WaZNFCfO0Focou/EMF8JAhl3ZC0IXpBk2LImumdLLeZI24ecvOosiv0
         wu39RENDa2Vdvsq0KFrJIani8EKJxOWyI0WZEWQsAIcqmixIQUB3cUqfg/nl8r365V3S
         Hdt9PaOuTtRibZlEYoj9YvaJSSu5XEwsReZwGaJ9FyGTA0uyzcUS/fVIjmi53OnQ8h0g
         8Jogmg8jbg5pdKiF0aPe26WOHLDKCUQihasoSe2EzhHoR8uAkyNZw+xsufc6do+/FoZZ
         NbuOVMFCl448XCkRTCQYqaAvuxSuB1NFQbaWUypyE4fCn7cHLnOQIDp28DTM63wyBDPX
         8hbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="n7fvTs+/";
       spf=pass (google.com: domain of joel.voyer@gmail.com designates 2a00:1450:4864:20::644 as permitted sender) smtp.mailfrom=joel.voyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pQoMTPfhUogrvOoEYLRdXq4/5Omyx3r2EGywVbl2iJU=;
        b=n9plzGXz6BzTZtH8Jd/iUejcoEHVl/XfUYF18UcU4v2NOv1Q0H7gAV+irt6+n1WpB3
         zmwXeQETswvOwEXUIy7KUTM35l6KtDuscP9DSjMeVvMuWW/172A/t5eY/SF/NUE1Dx8R
         qCywug4AMEre/NRld7p00ooJJxxEA4b1Z19b8MLRWbORDYzveMpD9lMA4NVBMQD1yVyj
         76ABOgRAooMWG6C9wEhAmixMDk9ouTdYNmX8flDrKAthboMVL/HkT1gsqd0oe9PqOifE
         VU7t3MfusZjk+fnahCI1lZtmzqVRdiHSeD2UUBb8mwppyPAZsdIWZ4nhh0BwUGSQYMMd
         yibQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pQoMTPfhUogrvOoEYLRdXq4/5Omyx3r2EGywVbl2iJU=;
        b=UC6ed7RKcRPIAZTJm/cbG0WvfdYXSiplrYVF38e+iGYNbvGXsZnAXHNQeETaltq7gs
         +3JJC3XynEJCs1P3RnHPiIy+Vyht2sS2iWZLEsvsOP42qWeU2HfScjmhlnGNejcOIQ6p
         X4gyDjD7kROuYR2DRmtPP74tyn0Ki+nKyp8gSCjnRlJyQQ+2+fCsUp+KUTYJ06IwpKaE
         aLD6AC0w8DywxXGWgz0PHs6OfMqIYdGiIEB7YakkxVeZP+cOg8Yz2hQ2iT4hnc+ETZNu
         dcWOs8FG7RRbhYk7jN/UCoSrNgbfwsiTbhUn/h56R7RrgtJI/6LxJlGM8av9EzcnSuC1
         FAag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pQoMTPfhUogrvOoEYLRdXq4/5Omyx3r2EGywVbl2iJU=;
        b=VRN3e8HF1C2c10KrfPjafEoq6nZDZLsl7b7ARLRyaZolRtvdj9w0Bfdgcmsk/SOJl+
         S/ZjbUgPYJjWHjRnxZSvud+FctxGt13L7WerrFu6ot4OQgSoFrCq4+Wl1x8+hZ/oisKc
         1t9aOnDSPJJUrh6HYXUPNDFZL9SFnz2SF+sfiWIWytRvFRBtxmiEqqra1Ealz7hFWMxT
         c/jDvE1XJn2leuuhTC2BYkJcsPQOggWKXcjY0bKOLpzYiReZwVfB7ekem1xlMgOOnc5I
         m16ztvr66QtXMo/Mn0egJWE0XsPCtjVa6LEDJ9Paoyr7bSej1vmES6vAqe1A767Krjn9
         EGdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53037SrDkIMd92xAnxlV8aXgMuIVdbAIYusx3kuonA+tXUcfLfwi
	BRaWgLiqbvZ8+scoiEzC3eE=
X-Google-Smtp-Source: ABdhPJzHkKTcFj7XZ622a+PwVrQiFptMWqecAREyJBO/XrdwZzELRJxxnuWc+YSjb/FnB2Hrio+0hw==
X-Received: by 2002:a1c:6a13:: with SMTP id f19mr7514581wmc.142.1592381014897;
        Wed, 17 Jun 2020 01:03:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f608:: with SMTP id t8ls1490916wrp.1.gmail; Wed, 17 Jun
 2020 01:03:34 -0700 (PDT)
X-Received: by 2002:adf:e588:: with SMTP id l8mr7549285wrm.255.1592381014282;
        Wed, 17 Jun 2020 01:03:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592381014; cv=none;
        d=google.com; s=arc-20160816;
        b=W58kq3/VL1nCVFnqe6HyrgPSyrNbRVGrEA3O6pzpqgtRcJ+7JGdy6PcVQuYVyMXm1z
         0QD5wpZA/sd2zRdgx1u9DfJ7+sQsOiWcpPWTSHs+aAsezyNYKaeLV3rSJZbeOjRxb0q6
         yVeJfKYtBkiGnLHTCFo1VNzvBf4qL4KG6n4mRxycqSHKgkMM92J/HGyR6Fe4LtwwjvRd
         J9i+M5Qto65/MC+YhLjZZDo8+5Q5h8M5wz2SXaw0u30Dj+bunDY41XLje6XvGaxQWc1m
         PmOkOWwkxaTN5eE634o84DF4INZKkmhnyJu/A2QWEy4ZFoA4+KLuxHwmlEjNHNxG7uVP
         Kttg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=IoLOTj4N/UivUbV7Xr+eQksZLmcOCCkaL8Z2FZzpaSE=;
        b=E13wkMYgFdFKUE00q/o95B10kaLkvhxZEIunSCokpGheL0t/+HY8j1MP7WhEw2WMiK
         vywZeuLuZpl349zqszFLRJtRrPSBTOgwL2KE2ryFkeiVqYiZpbAUg7+742wZjhMrgjBK
         eiH7l2Zy6okxUSwUcP7H85kzE0e2O2Aa+jleWxI7z13QEPHE1JTWVtyLoxBMTxucq1Z2
         Q5gx6rRTiW1654ZANh/Z6uCBRKc5NwDnm0jdkXji1V+i2s4mfFmtUzJTS7pLCU1uM8DQ
         znKpiQS4+2C/LX0ZW/M2/erq13wCe942NyDsspTo36yX6sLiBW5kIPB2nDokIYUUP391
         6oug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="n7fvTs+/";
       spf=pass (google.com: domain of joel.voyer@gmail.com designates 2a00:1450:4864:20::644 as permitted sender) smtp.mailfrom=joel.voyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x644.google.com (mail-ej1-x644.google.com. [2a00:1450:4864:20::644])
        by gmr-mx.google.com with ESMTPS id s137si245391wme.2.2020.06.17.01.03.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jun 2020 01:03:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of joel.voyer@gmail.com designates 2a00:1450:4864:20::644 as permitted sender) client-ip=2a00:1450:4864:20::644;
Received: by mail-ej1-x644.google.com with SMTP id l27so1327627ejc.1
        for <kasan-dev@googlegroups.com>; Wed, 17 Jun 2020 01:03:34 -0700 (PDT)
X-Received: by 2002:a17:906:1149:: with SMTP id i9mr6779545eja.100.1592381013809;
        Wed, 17 Jun 2020 01:03:33 -0700 (PDT)
Received: from [10.31.1.6] ([194.187.249.54])
        by smtp.gmail.com with ESMTPSA id n16sm12971271ejl.70.2020.06.17.01.03.27
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Jun 2020 01:03:33 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
From: Jo -l <joel.voyer@gmail.com>
In-Reply-To: <20200617003711.GD8681@bombadil.infradead.org>
Date: Wed, 17 Jun 2020 10:03:30 +0200
Cc: dsterba@suse.cz,
 Joe Perches <joe@perches.com>,
 Waiman Long <longman@redhat.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>,
 "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>,
 David Rientjes <rientjes@google.com>,
 Michal Hocko <mhocko@suse.com>,
 Johannes Weiner <hannes@cmpxchg.org>,
 Dan Carpenter <dan.carpenter@oracle.com>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 linux-mm@kvack.org,
 keyrings@vger.kernel.org,
 linux-kernel@vger.kernel.org,
 linux-crypto@vger.kernel.org,
 linux-pm@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com,
 linux-amlogic@lists.infradead.org,
 linux-mediatek@lists.infradead.org,
 linuxppc-dev@lists.ozlabs.org,
 virtualization@lists.linux-foundation.org,
 netdev@vger.kernel.org,
 linux-ppp@vger.kernel.org,
 wireguard@lists.zx2c4.com,
 linux-wireless@vger.kernel.org,
 devel@driverdev.osuosl.org,
 linux-scsi@vger.kernel.org,
 target-devel@vger.kernel.org,
 linux-btrfs@vger.kernel.org,
 linux-cifs@vger.kernel.org,
 linux-fscrypt@vger.kernel.org,
 ecryptfs@vger.kernel.org,
 kasan-dev@googlegroups.com,
 linux-bluetooth@vger.kernel.org,
 linux-wpan@vger.kernel.org,
 linux-sctp@vger.kernel.org,
 linux-nfs@vger.kernel.org,
 tipc-discussion@lists.sourceforge.net,
 linux-security-module@vger.kernel.org,
 linux-integrity@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <29829792-2C3E-44D1-A337-E206F1B6C92A@gmail.com>
References: <20200616015718.7812-1-longman@redhat.com>
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
 <20200616230130.GJ27795@twin.jikos.cz>
 <20200617003711.GD8681@bombadil.infradead.org>
To: Matthew Wilcox <willy@infradead.org>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: joel.voyer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="n7fvTs+/";       spf=pass
 (google.com: domain of joel.voyer@gmail.com designates 2a00:1450:4864:20::644
 as permitted sender) smtp.mailfrom=joel.voyer@gmail.com;       dmarc=pass
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

Bonjour,
D=C3=A9sol=C3=A9, aucune traduction possible,=20
En fran=C3=A7ais pour comprendre!
Merci
slts

> Le 17 06 2020 =C3=A0 02:37, Matthew Wilcox <willy@infradead.org> a =C3=A9=
crit :
>=20
> On Wed, Jun 17, 2020 at 01:01:30AM +0200, David Sterba wrote:
>> On Tue, Jun 16, 2020 at 11:53:50AM -0700, Joe Perches wrote:
>>> On Mon, 2020-06-15 at 21:57 -0400, Waiman Long wrote:
>>>> v4:
>>>> - Break out the memzero_explicit() change as suggested by Dan Carpente=
r
>>>>  so that it can be backported to stable.
>>>> - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
>>>>  now as there can be a bit more discussion on what is best. It will be
>>>>  introduced as a separate patch later on after this one is merged.
>>>=20
>>> To this larger audience and last week without reply:
>>> https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.c=
amel@perches.com/
>>>=20
>>> Are there _any_ fastpath uses of kfree or vfree?
>>=20
>> I'd consider kfree performance critical for cases where it is called
>> under locks. If possible the kfree is moved outside of the critical
>> section, but we have rbtrees or lists that get deleted under locks and
>> restructuring the code to do eg. splice and free it outside of the lock
>> is not always possible.
>=20
> Not just performance critical, but correctness critical.  Since kvfree()
> may allocate from the vmalloc allocator, I really think that kvfree()
> should assert that it's !in_atomic().  Otherwise we can get into trouble
> if we end up calling vfree() and have to take the mutex.

Jo-l
joel.voyer@gmail.com



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/29829792-2C3E-44D1-A337-E206F1B6C92A%40gmail.com.
