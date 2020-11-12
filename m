Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGWCW36QKGQETLZ7BWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A4AE2B0FA6
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 21:54:52 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id w79sf4830884pfc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 12:54:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605214490; cv=pass;
        d=google.com; s=arc-20160816;
        b=GOdu70VHFR3RVQOTGUzh+lNCGGm5sj1HCmapuC+NH4UJMBN5XPz4Lc+icYKX5iBoje
         72m4WXgYyAHG5VsK8vhFf2pFRZ7DfXBVXoTGoiYy+Wktmxz6F5oU2BwmCnthjCNvdxtU
         /LZBpY/yjiohK8tZ9asaNMGAr5yefYEcY5909Q+qbUKtggMz39kX86PK0Pv2pFCOyKRr
         b7dtXyi3ze2KmJRWV/PRRNd898tGLLWYWJ8V2c8IEUbxfU7FG0mvKJHFbU6tfoZOOQho
         WfygrC01+i+xlthpDZshKqjOZ2/YIJMryf3eG9wAXwDqOA9aGRPH2/wEahvVASXl6rzp
         2E+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IICp6Jq7AU9zqzp/inwFTG8NQMQwekl5uK/u5UJWL0o=;
        b=bm3J5UuPoH5bv81q49OmTE0RnAi7KXJQriTuny42LJyuTunCBx8nGbV6YrwJwi3OIx
         V3MddU6qCkl+n7Tm/MZDwH6FgDMVozwBiQXTzmuMRSXh7ak25QBWQLmCVk6SRhm2B2GG
         LWtgyCeghPRNWGcpgzw1HCkWpQITOt1BWhdOLuR6i5TJMF0OVz5gG0L0RJp/ST6zpJ3y
         isK3YahwtE0BvQFh08dLVGTDogDu9z+otWqFS3TIIEnQ3oNBg2fScLXuWUHmqsOnFz0j
         auRafdyjW1gzGjNkpGRBoh8wmqbL6JjE6Sjcny5FlMUB4fJ3+26ZvRtq0/cmvyPlB5F8
         QuWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ctgie1D8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IICp6Jq7AU9zqzp/inwFTG8NQMQwekl5uK/u5UJWL0o=;
        b=bPEVksU9zTkpaJ23dabEQfezrwp2o+kctdA0Ip25tJfQua3xE0vWBhP6N61Jo1+mxR
         oDXsSccpYx3MYIbzkclvOtgOf4Rs5cgJ+F9OdDgbB5wmHIIsOvrWnqIaioFtjFPjGyny
         uD3VkgfDzbAD5QIN0ZgFupjLyNBp8GcpOjHl3CUmdMvnyqIERcl+U9LQUeJnsrMyKA7f
         yXN3RT1hZ69qeCWLTfbvGWZ5lA7uAU0HHrw07nerM66oapIFAqFLudxmADt91GE4ylkV
         66rHhAwlwZxMDQFV4mVNZxsy4HDKcTRQUDVGoygLNna0XvRQCHSi+FRyvecIQqN0GlFj
         JlJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IICp6Jq7AU9zqzp/inwFTG8NQMQwekl5uK/u5UJWL0o=;
        b=BqXqB8p2ooCXWkmfxKrRW9hYBCeWKYzpLkxMYcimPIr6+ZJl+SmmHMxvPjBJwC8hZY
         HrsViVd8Ln46AGTEXsTcnRocaqEAnSrXEl+MYiZzp81c7f5rfTpStm6Jr0N/yDQhaZ8j
         SzSTdeLHxZpdUMAoN/PuPXQ6/faurmoXkksBJHPJDZIDXtZ7YJGv4CcypLeaVDIpkA7D
         dp2qEyCErMWFKR1aIzHieKcvyAUM+N7vG2icqjACTnG3uGrldkEpGaHqYwqAc3qF80PZ
         8zbSj2PxYR1N7/8IjNKzCMWFnCh0LWAteytG5wC8kYzvA8vV+mYMpR8r2T1Mh028V3TX
         S6GA==
X-Gm-Message-State: AOAM531ZLH3rWMU5NyRgvay/+/pTHaVg8PSqGWpj7rHPCC/4DAIkWDG2
	kh28sjX7NjxBq5Rsu+6brOo=
X-Google-Smtp-Source: ABdhPJzyovimAgGUHcX7Dm4R/qFGkFC3MyISFW45naBiLZ816c1GJyps54O13CCaTr+UcEkGCIpUYg==
X-Received: by 2002:a62:55c6:0:b029:160:1c33:a0f7 with SMTP id j189-20020a6255c60000b02901601c33a0f7mr1246614pfb.35.1605214490789;
        Thu, 12 Nov 2020 12:54:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:543:: with SMTP id 64ls1408423pff.2.gmail; Thu, 12 Nov
 2020 12:54:50 -0800 (PST)
X-Received: by 2002:a05:6a00:1744:b029:18b:a1cc:536a with SMTP id j4-20020a056a001744b029018ba1cc536amr1316632pfc.74.1605214490220;
        Thu, 12 Nov 2020 12:54:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605214490; cv=none;
        d=google.com; s=arc-20160816;
        b=qfKKyJphOPg0P+C4OB2K+9N67x+VDo5IkSGhVKWZs/rx0FWttWhHAXbbRFENHgBntV
         Jd/iPgYA34zgSX1Kzkdn3CPaMzJ9IbO6YGv1jAGT7A8R4p1+GsBd1FR+bLgof8C8C8BQ
         0vdBENU3RCA+erDOT3aXTdhjAJT0Jw7pySAZnGlUpFUxGEBIB6N8ye/kjW1ulD3ufl1T
         MDOgQKxnx8CyubiEo77dBhSrk8n25eeseGhga/sCv5qiT7ekfT955/KXI8OP01YOgS6f
         TgVqLq7iQahIBtynOvfB6ObQ183I6EHpDnltD5+zbcPXz+L95yBLTzXtb6msZTUkAwN+
         5g0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Kiz7admIpkh5f8na25jRX8719oxnjpCDxUfGo3ANCBE=;
        b=pdyBG2ZTtWk6MzkhuBB+4DDOm0AJwisNctzjy2bitvXcke4Oftz38xd8jd8ZycUOid
         A3O0lGxQJz+VUO7QD1cb2g061TrSM569cZBIRvTt4muXOwiSchaptXT4SbaO7uQG2deG
         QTLIReGyb1JLRdHr2NOG4wR+WmzEBZ6jy+eCa6YkBNq9UcoHVBQ1zEVqzTCb/pNqBQaJ
         U02cZ0nyYsHosx7zAnAfoHxYntoH8e56OE7hKkfOrhQea6of3+5OIWheIsNCmHo86DAh
         tv80N2CvilGsARM3FHPom+Yua/YZq/RPARyDgWMk2IpBLnpnse2hT49A84r/nTtwMKUI
         7T2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ctgie1D8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id iq1si499307pjb.2.2020.11.12.12.54.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 12:54:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id 10so5672208pfp.5
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 12:54:50 -0800 (PST)
X-Received: by 2002:a05:6a00:16c4:b029:162:bf9f:6458 with SMTP id
 l4-20020a056a0016c4b0290162bf9f6458mr1139365pfc.55.1605214489773; Thu, 12 Nov
 2020 12:54:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <0a9b63bff116734ab63d99ebd09c244332d71958.1605046662.git.andreyknvl@google.com>
 <20201111174902.GK517454@elver.google.com> <CAAeHK+wvvkYko=tM=NHODkKas13h5Jvsswvg05jhv9LqE0jSjQ@mail.gmail.com>
 <CANpmjNOboPh97HdMGAESSEYdeyd9+9MVy6E3QsvVAYuWVReRew@mail.gmail.com>
In-Reply-To: <CANpmjNOboPh97HdMGAESSEYdeyd9+9MVy6E3QsvVAYuWVReRew@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 21:54:38 +0100
Message-ID: <CAAeHK+xhjUQAtJThUHcaGmd3muBZHiJPfTqj59CMxo44hbDniw@mail.gmail.com>
Subject: Re: [PATCH v2 10/20] kasan: inline and rename kasan_unpoison_memory
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ctgie1D8;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Nov 12, 2020 at 8:52 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 12 Nov 2020 at 20:45, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > On Wed, Nov 11, 2020 at 6:49 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > > > Currently kasan_unpoison_memory() is used as both an external annotation
> > > > and as an internal memory poisoning helper. Rename external annotation to
> > > > kasan_unpoison_data() and inline the internal helper for hardware
> > > > tag-based mode to avoid undeeded function calls.
> > >
> > > I don't understand why this needs to be renamed again. The users of
> > > kasan_unpoison_memory() outweigh those of kasan_unpoison_slab(), of
> > > which there seems to be only 1!
> >
> > The idea is to make kasan_(un)poison_memory() functions inlinable for
> > internal use. It doesn't have anything to do with the number of times
> > they are used.
> >
> > Perhaps we can drop the kasan_ prefix for the internal implementations
> > though, and keep using kasan_unpoison_memory() externally.
>
> Whatever avoids changing the external interface, because it seems
> really pointless. I can see why it's done, but it's a side-effect of
> the various wrappers being added.

It looks like unposion_memory() is already taken. Any suggestions for
internal KASAN poisoning function names?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxhjUQAtJThUHcaGmd3muBZHiJPfTqj59CMxo44hbDniw%40mail.gmail.com.
