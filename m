Return-Path: <kasan-dev+bncBD63B2HX4EPBBL6XVX7QKGQE43RMP2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 973362E72C9
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Dec 2020 18:47:29 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id k13sf4855571pfc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Dec 2020 09:47:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609264048; cv=pass;
        d=google.com; s=arc-20160816;
        b=GeFtnhUZWpJgnnPOtrPsI8dl9mrJFwA+7LBs0ola/FPJK8ZTOuTrK+Bz0wVKFUvgeT
         V7Q/ewdzqvPXtaE9Ofifc32VEl/v3Lw9VscdZiZF0OCGuu8lxcODIk347BFL2cOprT0C
         QmmBF/2Z/cO1S1pSOeu/t8cRUJGNMCmrcZm6RMycULRIvPRPyHGWqqIs7qZZ/WTrP75X
         vRcl6PuFtaKAEU2waFsv3nJLkqwvEl1IdIzSosQztMXc13Lv34mg1KfH41gdBrADRhgA
         EVk7NpxvJKEyKedAbVl9AMl0DzEtjSt6OqF8y1/5xKN8Ir0HbS8YpqVm1mkLwIpUSa3m
         hJZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Xy6guubaKwZ9ZUWdmUKiK7aTFXVmhqB/lMUoNW5QV48=;
        b=NjkxMFPzEuCCXftQLrFBGMRFmO7RIG2SJnrbMNOfhQkzqMQmJR7jqPhHHHQPQIZBUf
         p5kZYEF/DsMDkz4Vr5imJJ3X1+W0di8kDmM8wATa12rzdS/UZj/0cYyyFcZGTgyOUoqL
         C2vHYnOVyhC3jYECWShWFThkWfHVpukLw248uhngg1IcAXCehgVJaLjrPWg7wE2u4OYu
         v6W+Zlpu7vyhyFxTPhPFrI6T9HtqFqnIjJPsqUpwWUtmWYkoTy0UhdItlr+d45aYUokM
         iQfOwV/kW4TKP1dXnUzejGaJVdCSIxiPgmkkbj+qhqHravG65MhigLci8VDNwBxvOVzT
         VsIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=MRz83igr;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xy6guubaKwZ9ZUWdmUKiK7aTFXVmhqB/lMUoNW5QV48=;
        b=UurGpT6Sc6AFZWKiaI9OW0Z623gR8oWj7ARUO4R51SxqvRn/PXuaxZFvDdZzek7Auq
         Pu92U8WnwOy+kEN9Hu5rPaHSRfJeWrCSZVY/pefYak+MWi30aGxqInyolqHq26IQyXiL
         bA2sjc7zezjsseZH5M0mYVjAUlFLUcLr8Q6AbLlnL5OWrAMRD+9sPFs7i1tvCCHZwEi2
         M/XyWoBAWPDDWAM1febAguYem2J9SMqncaSJB8hjLXb7s+zK2KrQOlkI9vRXGo8nb39J
         FOTz+gqMngJyGvhTh6GW46MHCv6ULGvTbGbX91PDTzBQ7GsbIktTq3iJnnVs5JHUXn4X
         BkuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Xy6guubaKwZ9ZUWdmUKiK7aTFXVmhqB/lMUoNW5QV48=;
        b=gMAE5kCZtaxNEb0+q9KdrtBAQryoaFEjy0oIlVMMfaYtiyFIdOAMbGi4RaWJoK16LN
         Vov9DbiRQ8vQNSQAHlUNVincDEdqLcc8KfJ61cl/7ydLKv2MdVhNfnUzMc9ZHQm7/V+y
         ElZnFJ0eEIdxvU4yxrmruyGrOd77qEBkBFtQe7GX1kNEpyo9c5xDBSzTBg1KMz90axgs
         Umw2KDMlJqEP1fGnEXwV8dknTSKawfHF4VTkjnkE6qtguPrMHPq7Bdqbn8/Gb/i44dP1
         KM8cfe8KtyUmBSC5sIG7Vb+suAsN8Tihl+OviHmX8D3eky9ZF7ytfJ0CtV80xsoXDG77
         W92A==
X-Gm-Message-State: AOAM5322FHOpQkal324Rs6W0JQpQdA0JkavNtSt/IAwnjhCOOuWYu/nT
	WFv9PouoovHtSWty2g80IwA=
X-Google-Smtp-Source: ABdhPJwkKcl32P8sZ4rSwH52EwmrMYzBq2rAPss4f06FaSUHO+lHADN6UY+8cMLRhslHoVGKi5bC3Q==
X-Received: by 2002:a17:90a:4042:: with SMTP id k2mr5038157pjg.160.1609264048076;
        Tue, 29 Dec 2020 09:47:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d713:: with SMTP id w19ls14052104ply.1.gmail; Tue,
 29 Dec 2020 09:47:27 -0800 (PST)
X-Received: by 2002:a17:90b:8d5:: with SMTP id ds21mr4820213pjb.5.1609264047528;
        Tue, 29 Dec 2020 09:47:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609264047; cv=none;
        d=google.com; s=arc-20160816;
        b=GCb8a1jEYNNYmxQR11Afi13hncwGGYdJDujo7HKiL9k5M6SsJrrOY5FBt/I5mLARDX
         6ZhfubTFWdOwdACL196nMq2h6lPZKDnzEbyJJzn1kTVo/Z6BQNT7E6ZKAPqh4etOMQVT
         ZrQH0vA3QT4KEltX8qhiFRKA3wpUmxkfVFaQtxGukCtAGf5NrVY6ii/rU22K8XG2cUmw
         OxuLKtnmaw0ikY44WA9QSB82sRuyYPFJEv8KjU4hHnZ5cYyU5t9Hk0yIOokub1t0jMOh
         74L+TTNbattjZ+UclX3cGH5O3z+H60oMBELlcZ29YjP2bblp332yTtYEB/XTfdUybAnR
         vu6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=IOQR6Xa0VjYfeMskFH+7bEtcy+HiJPpOnLv7JHB2vt0=;
        b=zIpJCWFhJUXnudy0Dwn/DSz/E/F2Z6QccYqgFyWLsj7jVY0dB+1n1U29hKOocAu16q
         DwbPr50BXk8SZo+PI+oZAdJd/v3dLuvgBajIFpyWj0rfRouF7W+Ha6QT4f1+0fz7IQBp
         ryU+1ZKr2TwGRL8cwn7sPivReTQ3JAA/x13bRYR7NRIx0fX5olL78yof5As/CzHbUWPg
         9rZ8SetQWNYUyqRS526HaNI/aEf2Ui8wEbQGlgoTpkkGiq1k3DpI2hLJtq0ovQqSTRym
         CdRVv4qY60ihrQIWHlUY9N94lfqlbWiE8/VL+ABWazXJBPcRgre7ZlRQiGmf3/UOKEA7
         xaiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=MRz83igr;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id w6si259544pjr.2.2020.12.29.09.47.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Dec 2020 09:47:27 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id 11so8344385pfu.4
        for <kasan-dev@googlegroups.com>; Tue, 29 Dec 2020 09:47:27 -0800 (PST)
X-Received: by 2002:a62:844b:0:b029:19e:62a0:ca18 with SMTP id k72-20020a62844b0000b029019e62a0ca18mr45920844pfd.46.1609264047236;
        Tue, 29 Dec 2020 09:47:27 -0800 (PST)
Received: from cork (c-73-93-175-39.hsd1.ca.comcast.net. [73.93.175.39])
        by smtp.gmail.com with ESMTPSA id d203sm40492357pfd.148.2020.12.29.09.47.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Dec 2020 09:47:25 -0800 (PST)
Date: Tue, 29 Dec 2020 09:47:20 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201229174720.GB3961007@cork>
References: <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork>
 <X83nnTV62M/ZXFDR@elver.google.com>
 <20201209201038.GC2526461@cork>
 <CANpmjNNTuP7w7qbwp7S2KU23W0pvNrOk8rZnxzRYsxAcOXMO8Q@mail.gmail.com>
 <20201209204233.GD2526461@cork>
 <CANpmjNMXOYkG25Gt6n54Ov+pxVjGMXRUWAMkDD4JWtLCNq4jPA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNMXOYkG25Gt6n54Ov+pxVjGMXRUWAMkDD4JWtLCNq4jPA@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=MRz83igr;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::435
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Wed, Dec 09, 2020 at 10:44:53PM +0100, Marco Elver wrote:
>=20
> I was curious, here's what I get -- sysbench I/O 60sec, 5 samples
> each, reboots between runs, VM with 8 vCPUs, but using 500ms sample
> interval which is closer to what we want to actually use.
>=20
> Static branch samples: [7272.36, 7634.77, 7380.72, 7743.89, 7480.7] #
> Requests/sec
> Mean: 7502
> Std. dev%: 2.26%
>=20
> Dynamic branch samples: [7354.06, 7225.33, 7154.76, 7535.82, 7275.94]
> # Requests/sec
> Mean: 7309
> Std. dev%: 1.78%

Finally ran our benchmarks as well.  You'd expect a lower result because
most of our work is done in userspace.  Then again, I've tested a config
with kfence allocations every 100=C2=B5s.

So far I cannot see a signal.  In one case kfence causes a 6% speedup.
In one case there may be a 10% regression.  Most load points are either
perfectly flat or have the usual random noise.

If I assume that the 10% regression in a not-very-interesting load point
is real, I can go from 100=C2=B5s to 1ms and happily live with a 1%
regression in some dark corner somewhere.  More likely, the 10%
regression is a fluke, just like the 6% speedup.

Congratulations!

Performance is too good for us to worry much and we have caught two bugs
with kfence so far, with fairly limited deployment.

J=C3=B6rn

--
Mistakes are the necessary element of any contentually significant behaviou=
r.
-- Thomas Fischer

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201229174720.GB3961007%40cork.
