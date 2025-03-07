Return-Path: <kasan-dev+bncBDW2JDUY5AORBHMPVG7AMGQEBGLYUHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DD69A55CB9
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 02:10:55 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-43bbbb00891sf5344975e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 17:10:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741309854; cv=pass;
        d=google.com; s=arc-20240605;
        b=eEMW2PDm5WdBomv9q10+2S6R1JNuIGq2w08hqfpUapyC8fCw3MVRZknINv9L4jguCB
         gtpbLnCv03eY9flYG9IUVN+YGEaTz3L+9WIvCHPu3LvomQ63G6N+aRTH1IQnmqVocJ3+
         L1CYw6hFCkn4A2HAzNXwCYJMGoGFguggooqtx/8ok6TWc9qp5bPQDa7NgeHyDFTaX7Xc
         c5dbb5o2JxEil71z8KmAbGN/3Bycqhg4DbJvyLKF2v+ORjlwReY4N4U+KI6UIlUin+Mc
         S+4dbyyB8OuwZ6EK8YMw8ialtSv27s74MPTiAkDKcD4ALeyPzMvbIu4h3Ol/fBe5S6JX
         u69Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Ylf2jAeFmLykJzZcfyUGYzy0uQz65PDz7lsWw9egnhw=;
        fh=9wZEPxVAgGD3Bib/aT7Qms9BtlgQbFhGN7ol3P4xXQk=;
        b=QGbJgKFtz5eyQ5vtkOgrmzhCKpPY1Tp9tHbaPzBONJ6bRs232r+rZ5J3BKVrFi/RQX
         BfX7L82TFP/ToNLwXX/ry8/tbN2s5LZkuemoDm96565hwtEpX8uNt3WEqyLtKdlB3zPs
         pA9fz8RXpGvPog3OcEsMcoPkVrNWw1Rpea5Lyl+q6MnneYO4MmfCbUglEzNlF5dL2kbV
         aaQTAKa4Vl4hVchyqavjL8+5WuUcwvuXW3TgrxS87smOFnbtkskEP6w0QqPe4L/2HaAP
         shUeqm0fn6bT3JgrzD29iOUXZuLEIdALi+p0xXf29kfWybU6Wl9r0PBi2TuYdoq3vXzI
         2Jdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=N0ZT5Pat;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741309854; x=1741914654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ylf2jAeFmLykJzZcfyUGYzy0uQz65PDz7lsWw9egnhw=;
        b=xrfxW2u172seKWsJNN5dvKd5NhK+X6FX229BS0dbMoOwddQg/MzkLG2kl5ib+/GvTz
         MbI7vnNThIGi8GEyqUdtN6OJzDYlBb525JrBjUn3iB0d1O7jrbpVuXk8hQ4kOy8mgGdx
         hP//eODO3Yvk9i/ca/9sLiFORmP95uptBGCEgXfmEyK24LwYvRs0Vs+nu3Zec+WCUhHj
         C4zmmuSDkNNcePG6XzTrZrVhHdPjO3Hm/TASV4DlxVY/B8QZp7J0GzQn2gUqPq2mYAfP
         PkdjEatOaJWw+is38woxYHXJSgjijy1Hwbz5mxZjUcL7ZdptHvg6lEgVEqWyrf9/4/Sq
         dcYg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1741309854; x=1741914654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ylf2jAeFmLykJzZcfyUGYzy0uQz65PDz7lsWw9egnhw=;
        b=h0EbCdBAUo7qEAaiXu1LDKfbtcgDVROVRK/MEoK/02XE7XSNkBDWKAOxSnWsfsp8Wf
         7RO43pGBv8Q1/oRljvUZefMaWfJa8Nwu0GdzsOynd0xfqu5OaF+ApvAN+ZN/ofa7+FsK
         uSwfzvuZOJbVNFVSobFj1+69as2jDJMSA5mLRc+p3r36t/zb07d1IlLsToTszD/+Rn3z
         ySDXewxX/nDMGdhXrWz4herFWY9Ae0TG7+r13gXcG8GjamXCs+Lw/FW8nh2CJmzbPNpm
         6I2S39scQ4u0yZXnU4MBso+6g6/egQ9+VvUbQsh8eCzo2KySX0RIpyEQMLRG5c+M1mDl
         tzjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741309854; x=1741914654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ylf2jAeFmLykJzZcfyUGYzy0uQz65PDz7lsWw9egnhw=;
        b=wg+P+Z56DaXTThJ037jdEuGrA+0o5tNzX4TkSTSDQMtmgt+UMVzbvrnqyjyM/wEPCn
         3Fz7q+wmzmmCYeN1HdFA0bKKVMYSt75r1yPZHl7r9XTHAMYH1rCR72iru4p9gZaG4B65
         JhIY9kPoE5uJRFFTkGVfKYLeG75ii+WCNGlWpiCHfrzN6Q8+nXZX84iFl/NtipkYRXRa
         onhtnGcfA3NFfX7AF79QP8mRCuRkigOQAgo6XNBWrUdrbMbcLldCn0qO4OlwEhbOrDIQ
         8csdfYsbFGusOWywbMFi8iOsahkiVhd3+KqQoFpKK9AZjyuJdgtvp+PIck8Y0GHEGfUc
         b1tA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVPrHFjFab5MAk/8CmC5AVIHa7huq9ufXSjwohmKm+t6cpIYYa9jkXNiauxDNyneofKfjrZg==@lfdr.de
X-Gm-Message-State: AOJu0Yz57olCl+e8c7sk2Q4Z4GqZOs+/O/zKbBxPbgUwHtfSNmpIZR2v
	APjeSV3ggWpp8lL1W6575AC9WzjDH28/Y+SA9TR7ggFvqDZKoKuH
X-Google-Smtp-Source: AGHT+IFt9cZnCRjA9cjxZmYc11YMIiFK6Dhp/85EnyLotqxQkIEL7mEY8CVSmEuoajAH6y07W/oOzQ==
X-Received: by 2002:a05:600c:1d1e:b0:439:9698:d703 with SMTP id 5b1f17b1804b1-43c5a631652mr9430015e9.23.1741309853417;
        Thu, 06 Mar 2025 17:10:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGeI/fXQxuwMcRA1jf+Vdn5KcDKGvbBA7K/P8AyN2JDfw==
Received: by 2002:a05:600c:58c2:b0:43b:beb2:698b with SMTP id
 5b1f17b1804b1-43bdb28f703ls2559655e9.2.-pod-prod-08-eu; Thu, 06 Mar 2025
 17:10:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVZhE7yeCFNhtfFiKzmXPZrRj+CqO7IM9CMN5Owb3BBEhwsp6b5s5hrKdyAofCt+2P5DOw8S+VA0jw=@googlegroups.com
X-Received: by 2002:adf:a40c:0:b0:391:ab2:9e76 with SMTP id ffacd0b85a97d-39132d47102mr485066f8f.30.1741309851004;
        Thu, 06 Mar 2025 17:10:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741309850; cv=none;
        d=google.com; s=arc-20240605;
        b=le2HEJpxvYcnTH24Fx6bTeBw3YnE7pPtJsi1sPiG846xwJzKZI3InX7RkWphoFzjZ3
         N/B9nYv+1uOPjVw0JqWWsC1dyQW1i2oQhxLNK7RUwTr7Nn1hMIbo8/2pSpgunvJvIsun
         +LiwXA5yClQ6Rqdn5QwXcAsU/2XFDHA5O5rX41ephAyNzgVsycUYso1soE91919RvSMK
         1Mbnc7+tfFO6xzNTTSwD7dx0v8Q3GZaECz01ZrMTeXwg68I8WD4u5UPVByosIguiAtfO
         XDZIFEuUuKYZnOVwRNeve5mMevkFGowMUGbxJDMe80wFFIwd4AWe963Vfw6f4XecdmTh
         LNDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=U8W4lBndXbHt9de0ee6upN787KMW52umATu2vsi2G1s=;
        fh=w0hqIRtk34IvHAZTv6pDkxfezXLkJaMELfxAUdgygxA=;
        b=SEuBhc0ZKy/oUivSZA497s1bkta1GGOIdyL3CSbw+2eNPaejWjm4lMrAPTmGDNHRP7
         9w5ZUGECGFEHS3Isx10KzDTi1f4dG6EZqf2wDLRoFqxZkwS3tvT2H+8G0DzIZxX8a5wU
         Cnur+K5zq9lLdqG46SVnY/czP+9pmDOCn88sa1tzR1iySSnVGHfroxMvXUDFOXfey4br
         fNbJQMTj9rgYQKcR1P7pQ/RUifEmaPC+JUfbB5Wnbe5dWMwVKVY5IOi9ao1Zgya2Wjex
         2wyB0G36Ee74JdElJo9+zzuMX6rbGBTIHumfng3Wa+LzVIj9JBlPb3xfxgsBPMcGjwmF
         GcGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=N0ZT5Pat;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bdd8c530bsi416595e9.1.2025.03.06.17.10.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Mar 2025 17:10:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-4394036c0efso7514815e9.2
        for <kasan-dev@googlegroups.com>; Thu, 06 Mar 2025 17:10:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW4N14CvN7jb1ofIPskEtypLNmwed/5c2TnmSnsX48SWzpPdpcWfPvMBHz3mqscsXNYKUXtV347H8M=@googlegroups.com
X-Gm-Gg: ASbGncsb8vCYF1uh/4476ndoh0LlGTSsEMfulkqhCso/DOT7VRXRbuhpJbSLpWMZkRQ
	bPpg2kz1OFP7m0WJlhXueklSZbeQZOKghFvJqM+nJHwPcceBCb6nzFBZZ66ty6BynLFee3OsaqF
	7VjqCmgJWJIKLUfIHSSrLqQd1HmJv+
X-Received: by 2002:a05:600c:6d8e:b0:43b:cc3c:60ca with SMTP id
 5b1f17b1804b1-43c5a631736mr8352965e9.21.1741309850252; Thu, 06 Mar 2025
 17:10:50 -0800 (PST)
MIME-Version: 1.0
References: <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
 <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
 <CA+fCnZeEm+-RzqEXp1FqYJ5Gsm+mUZh5k3nq=92ZuTiqwsaWvA@mail.gmail.com>
 <qnxlqbc4cs7izjilisbjlrup4zyntjyucvfa4s6eegn72wfbkd@czthvwkdvo3v>
 <CA+fCnZdUFO0+G9HHy4oaQfEx8sm3D_ZfxdkH3y2ZojjYqTN74Q@mail.gmail.com>
 <agqtypvkcpju3gdsq7pnpabikm4mnnpy4kp5efqs2pvsz6ubsl@togxtecvtb74>
 <mjyjkyiyhbbxyksiycywgh72laozztzwxxwi3gi252uk4b6f7j@3zwpv7l7aisk>
 <CA+fCnZcDyS8FJwE6x66THExYU_t_n9cTA=9Qy3wL-RSssEb55g@mail.gmail.com> <xzxlu4k76wllfreg3oztflyubnmaiktbnvdmszelxxcb4vlhiv@xgo2545uyggy>
In-Reply-To: <xzxlu4k76wllfreg3oztflyubnmaiktbnvdmszelxxcb4vlhiv@xgo2545uyggy>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 7 Mar 2025 02:10:39 +0100
X-Gm-Features: AQ5f1JovwqbYdeSGr0-fcudbS7_ChDFAODKKUUmrprBtHFAHDoFjM50Rrc6n6VI
Message-ID: <CA+fCnZdE+rVcoR-sMLdk8e-1Jo_tybOc7PtSp9K6HrP5BEv95g@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Vitaly Buka <vitalybuka@google.com>, kees@kernel.org, 
	julian.stecklina@cyberus-technology.de, kevinloughlin@google.com, 
	peterz@infradead.org, tglx@linutronix.de, justinstitt@google.com, 
	catalin.marinas@arm.com, wangkefeng.wang@huawei.com, bhe@redhat.com, 
	ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, will@kernel.org, 
	ardb@kernel.org, jason.andryuk@amd.com, dave.hansen@linux.intel.com, 
	pasha.tatashin@soleen.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=N0ZT5Pat;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331
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

On Tue, Mar 4, 2025 at 3:08=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> But looking at the patch you sent I'm wondering - are we treating the ari=
thmetic
> in kasan_mem_to_shadow() as unsigned?

The shift is signed (arithmetic). But for the addition, it doesn't
matter? Adding an integer to a void* pointer should result in the same
value, regardless of whether the integer is signed or unsigned.

> You wrote that all the ranges will
> overflow but I thought we're interpreting the arithmetic as signed - so o=
nly
> positive addresses will overflow and negative addresses (with bit 63 set)=
 will
> only be more negative thus not causing an overflow.

Ah, yes, I see what you mean. From the C point of view, calculating
the shadow address for a pointer with bit 63 set can be interpreted as
subtracting from KASAN_SHADOW_OFFSET, and there's no overflow. But on
the assembly level, the compiler should generate the add instruction,
and the addition will overflow in both cases.

The important thing is that both possible shadow memory ranges are
contiguous (either both start and end overflow or none of them).

So this was my brain converting things to assembly. Feel free to
reword/clarify the comments.

> That was my assumption when
> writing the previous checks - we need to check below the overflown range,=
 above
> the negative (not overflown) range, and between the two.

It could be that your checks are equivalent to mine. What I did was to
check that the address lies outside of both contiguous regions, which
makes the checks symmetrical and IMO easier to follow.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdE%2BrVcoR-sMLdk8e-1Jo_tybOc7PtSp9K6HrP5BEv95g%40mail.gmail.com.
