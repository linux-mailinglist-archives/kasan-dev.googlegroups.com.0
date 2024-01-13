Return-Path: <kasan-dev+bncBCV4DBW44YLRBX5QRGWQMGQE3SOHVMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F53D82CACF
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 10:31:13 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-680c88d31f6sf104870906d6.0
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 01:31:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705138272; cv=pass;
        d=google.com; s=arc-20160816;
        b=tfrQjtKo+TfenWT72VqlfVfioZHo8pDGXsNNgCMoikDRYIHku3elAos0rO9BpVQD8k
         hDY2DV/axLau8sn2x3IvWN8yl2JVHFtMj9fdxNDX9D6GDa7Tbe6PHX4j6fmFYoTyGB07
         dsFpR1iOAGwqp+nl2mGFrc2oHpOSGvgAloFYOk8QSbjbFHCwVbUqdw0UgEgWMBBOZw8J
         6j7Qart6v22dr+0H7Dh1cGH4umqS30xxryO6k+OV/sq0wUyDcRCwKs5ac+/krwVFhDuL
         LV43FbXEvQmaImI6Wox2jJY2bv/stSEzdr4UAVO19ulN10WPgoFkzHLnAtWb7eHFHEov
         cJYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Xbg3rn0YshYN6EoiaMZJxx5OBeitb1jVqyPejbmmKwI=;
        fh=ONaZ8uza6Q326KbPaYGMvUxVeaUBtspBHRgl2IaUgF0=;
        b=hJOt00XIgUVeApNysLTsgS3W+SVn696hfnQg7lhEcTtTxcvl7P2TOtzYBPpAfXGnCg
         CPRLqZIM/D0UNlT5Q84e7Vzpsz/0oMocqsUweoACloBDYsAqCsgJJyKKmfA2tEq6cmjO
         UYM1Z8IlkewZ2Ode2qll1TJ8tchQxVzOMUSZvwlCF1a1ZJ5fYLJETJMgOD0IL5lfg7VI
         9hRTRvybOIDNpao3oPeAef6TATfPorgaVw0Y5zbaxwT5aq099oTAntWByXdjxG7epWUs
         9UJIDcnuBU6e5wT+nZMApFQSSnXc74Ea5uDG785q1hXpuXlVbQlKAjyVxlBUiwV7yKCF
         GFcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W8NCNXA4;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705138272; x=1705743072; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Xbg3rn0YshYN6EoiaMZJxx5OBeitb1jVqyPejbmmKwI=;
        b=Qj4Fnc7cH3G/dCE372U9BlfCABs9XJJqFLpnyVxahhwHIa3SekLAsKU1zSLLIlkxex
         PQv3ypazEQpps9xp93kLE1wsXqUuOdHDOgeRwx0fi+P6C6vP5/CMOAHvQGblU4Fxtrx6
         zS+zjBTzVVXEBDo1wOWDZSBkYi3DXSRC/6FdI5iwBLBQa+NkSLWXtICzUDHaeCZSPdhT
         INqTvuQeEZDK7euRwm6sL7dh/VTZVQs1It5t67w/rf3nMpLoG40siEICc4WE2iRHQzj2
         eSNPvIK+rjNyTEJaYNI51BG3N5Q8k0zKRm99aaMEkKqNtC2CYaGmvSaPvA1n2fgI1cds
         0e9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705138272; x=1705743072;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Xbg3rn0YshYN6EoiaMZJxx5OBeitb1jVqyPejbmmKwI=;
        b=BGYG2hxfDDrpktxmQrz/5L53x0DCclJ9eV1j/EJksDE3BGvdcOOENhdhiC826Kc+5V
         w0DBUZrRdPk9PBTvEKMmBGdnoWUTSDckdZknDrFdSD2bkIlq28wzMZZhNT4WOWoypK3c
         ZtaYAxK6Dyq7SUr0l+kT92jZmjZn0EQhp5bYEZRiCbovgft4rE63Zi97TmE9dDVOHa4B
         fk5q8bUR0mZpEZkM+7lBWtcV5l+XXEXcWioaL7jkAEo6ujyNgQ412MjvBhFRs4Hax8V8
         tWDaMxE7uu14OsoIvsgexW0+cJWTawrgkdjn29Oz15A94Gzbn7wNml3FC0NAYtq48iyt
         iAOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxpri1NrL5DPvKfjhCwjzRKny6f0SMxR2yFDQzJcGIAM5viV3G4
	eijEG9j8QYPwme7tJ8DCp54=
X-Google-Smtp-Source: AGHT+IEv3CwDMPIU4XrJBN6zLPqQz80wfBIIUwsOSeR9YebXHQMpMyFj7IqwGpKFc/tWJ/9WdlxSnA==
X-Received: by 2002:a05:6214:29ea:b0:680:4c8:a495 with SMTP id jv10-20020a05621429ea00b0068004c8a495mr2064384qvb.128.1705138271943;
        Sat, 13 Jan 2024 01:31:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b31e:0:b0:681:551c:1348 with SMTP id s30-20020a0cb31e000000b00681551c1348ls19982qve.2.-pod-prod-08-us;
 Sat, 13 Jan 2024 01:31:11 -0800 (PST)
X-Received: by 2002:a05:620a:2491:b0:783:13af:fc88 with SMTP id i17-20020a05620a249100b0078313affc88mr2901353qkn.81.1705138271126;
        Sat, 13 Jan 2024 01:31:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705138271; cv=none;
        d=google.com; s=arc-20160816;
        b=JNOqNZniWnYda/D5f2g0T16fgGENsAKsA6bgmj/tg6QVkxwdm/aQPfylSVxhgIMqS/
         WBTBSR467+KPFz8V7Q4cSHpLzv0X0/FMJNY5ptwmqK9XODj0Gi8kg/QpJc6/pFK9kStO
         9arRlh0muP8n0P1Qc2HsRrjHCZfgKCAndZVJ0tPDBkcFsB8XkVLPJuEZvfxyW0LO6cNS
         GorPdIW6Vxsei71P+3tzHVgdFM1QYq13/izbOMn1oPQth1h/N6wOf3rmb48pOuCJWweL
         PL4rbpmjXRkI7AhJnmD/WIFamzsh5ZY7S4I069GWx8iJRJxzIkEFGzcBTdjByco9v3wG
         oYGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/MfQVj9eQZkESv1Q+8pI37q/xl6WbuISU+fGulwlTaY=;
        fh=ONaZ8uza6Q326KbPaYGMvUxVeaUBtspBHRgl2IaUgF0=;
        b=weGvuoaez2QEypiBFmsLRgF+XJ8eAFc3ynrCLAv6WgQN6ahZqWvLP03YcFJ0Zh2ZLH
         /C96KnUWgKHL+kfnC05fz6EDIa2Bo7P1MXrFvVfEu5eARXH/p1ZEJJl97oO1wk9yLU+4
         KOpezyJckCkIghdvErUEhE0/Jch8im8UDCtY2I5bNDtoshOKf7fIro5ukCAY6dCxnn8C
         lUgKc/KAiWJKs/f/t9CZaRPM3GzXiFr/u8Q8bxkm9IQxlyUYvLkn/RCiAi8hEONTi2PX
         UgSBXvtS05Kk/ZUUS1LGDmaRZWs3d95mveFLXS85d5N12q66s4qkHLzf1fnuAL/nTy4W
         1hKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=W8NCNXA4;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id i28-20020a05620a145c00b007832b0749f6si362545qkl.6.2024.01.13.01.31.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 13 Jan 2024 01:31:11 -0800 (PST)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6600,9927,10951"; a="463646409"
X-IronPort-AV: E=Sophos;i="6.04,192,1695711600"; 
   d="scan'208";a="463646409"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Jan 2024 01:31:09 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10951"; a="956337463"
X-IronPort-AV: E=Sophos;i="6.04,192,1695711600"; 
   d="scan'208";a="956337463"
Received: from tassilo.jf.intel.com (HELO tassilo) ([10.54.38.190])
  by orsmga005-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Jan 2024 01:31:09 -0800
Date: Sat, 13 Jan 2024 01:31:08 -0800
From: Andi Kleen <ak@linux.intel.com>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
Message-ID: <ZaJYXCVKA_pDqLqn@tassilo>
References: <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
 <ZZ_gssjTCyoWjjhP@tassilo>
 <ZaA8oQG-stLAVTbM@elver.google.com>
 <CA+fCnZeS=OrqSK4QVUVdS6PwzGrpg8CBj8i2Uq=VMgMcNg1FYw@mail.gmail.com>
 <CANpmjNOoidtyeQ76274SWtTYR4zZPdr1DnxhLaagHGXcKwPOhA@mail.gmail.com>
 <ZaG56XTDwPfkqkJb@elver.google.com>
 <ZaHmQU5DouedI9kS@tassilo>
 <CANpmjNO-q4pjS4z=W8xVLHTs72FNq+TR+-=QBmkP=HOQy6UHmg@mail.gmail.com>
 <ZaJVqF-_fJ_O3pJK@tassilo>
 <CANpmjNOz7tBMK-HoyZNVR2KcgxEBY1Qym=DRa9gHLFkaNHLmVw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOz7tBMK-HoyZNVR2KcgxEBY1Qym=DRa9gHLFkaNHLmVw@mail.gmail.com>
X-Original-Sender: ak@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=W8NCNXA4;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=ak@linux.intel.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

> This function is only refilling the freelist. Readers don't see it yet
> because it's in none of the hash table buckets. The freelist is only
> ever accessed under the lock.
> 
> Once an entry is allocated from the freelist, its size is overwritten
> with something non-zero (since it then contains a stack trace). Those
> updates are released into the right hash table bucket with
> list_add_rcu() (which implies a release).
> 
> Am I missing something else?

It's probably ok semantically here, but at least I would be consistent with
using the macro for a specific field.

-Andi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZaJYXCVKA_pDqLqn%40tassilo.
