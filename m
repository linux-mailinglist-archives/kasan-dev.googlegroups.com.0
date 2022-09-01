Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAHSYGMAMGQE6UYJM6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F6045A92F7
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 11:18:57 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id e4-20020a5d85c4000000b0068bb3c11e72sf6079287ios.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 02:18:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662023936; cv=pass;
        d=google.com; s=arc-20160816;
        b=J88ZlPinrTxiskaN/zZMj0MRZgZKyJ3EOhZVbUJH72AmHLnfCZnqK5+dLktewFDmTG
         Len7k1G8TbT8v/ZdHDmBLDwDSdP7i7A71ACU+iQ3s3rKNLzK/rMuEUO2QXSkfBbu0qkc
         Q9ECetC3CSl7zvzaEkTSc15jsxSjgvivzDOCNs/GQhoqarKf/DArhMUnPJ5qi8KSJwyB
         HHbf6rtGs/hFfccqANIpi+BR/EYoy73B2clJ5567nE4xvL/TgJfHrSp1wTOKa+QHDsBL
         zxCSrKF1u/a5GYaYKN3+vgJFWAjF+8pUA+CxWPlTO6r3J+RQqzkQ4p9elRZeCl7kz2iH
         vTbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=J1boh3fMHMWCkrJLijiOvTvZTX07ZASFB6CVX+D4V9Q=;
        b=D3mzexcmVInjRNWQTptZknvNEIQ5k7n/HQChDa4wU8Q5/ijgkHvAzZg4AgRp25OAkK
         V7keBGAaEsQ6emVog3zZL5RCuM0YSBP7Vy6C/FeBwrhtFXXRaE/MjKjWUGp6jvZWgw87
         TvCzC9nNS9EC0m83Cqnyv+iiFDLkG/h0VinLYlkdmPWx9gjOX0O9Zd4jis/ZFuoDdJbi
         2E0dJvEP5F0bAoMURGfYeud+ErkXRPyHf7JpRf2JzIsS5MhXYoSGTwTOJfuYTLFviawe
         T3quBJx6Y6Y8mSyaevu9y557O65DLDFBe9I3pxsvcETPsBp7KGw71BQivtk6hbbbePH8
         EvEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DNWL+HfE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=J1boh3fMHMWCkrJLijiOvTvZTX07ZASFB6CVX+D4V9Q=;
        b=t9U3Zpa9fiG8/VqleOVsNnN10Q6LL4WeHFeHB98KVmB9uy/jTAixpOV9lMaR41imDm
         Xphw0MJoMZvSpKcucfm3goUDHHEaVtDJapD7cWKMftGyPoSM9PCvzUVvmEkV0euV7IWM
         ChjsLFgoui5K2mawsMcuKwD5F9KRpdXcy8HWh5Z1oALkp353ula3vzhHMsou64S1+EQB
         QyVY+9/pWPYMlcBSk1Xzt3j7lkS+F+vshSBOHg+1SC52VGDadMMsvdG5kMN41RLsVJKC
         YI14SfLl1jlioHQWoiz/GFl3qOBCSYzSlwfgrbA8HB4eSnmBFIcaaSD8/PRJaerQ4vb7
         KxYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=J1boh3fMHMWCkrJLijiOvTvZTX07ZASFB6CVX+D4V9Q=;
        b=Tss/psRJhmHVAifCt7sLbfbpuqI/s2BkvdV7FXG979m2NyIQ8vYX9pfIP5yEC+m0ua
         yL7LejrygXsdDFmxTXRRaNCXDqYqzrCHJrRlwnf8gJv1lTme73jTpyTfIPyywkLJvaUK
         6OzoSC++N30vWnseYpD7yz+4717hrUxc64Wsc7flquX/B3A/5XIFkR4L+iisjKfM+ZRD
         RpksbclEawT0sWwRAFGDBtkGaj5sP06BJhBZ88hHpUofTJy1NgzC8VcLGIZBGbgUVlon
         lEfLzCPugFNucugq1jfkyx/srisKic7GyM8ozSzFHlodliziBRZqgGHK8f2bEbno5G7r
         EsUA==
X-Gm-Message-State: ACgBeo3Whxa2RG10JxWDmK7dyk1Yl23DrE9uh3hoZWxRKxBCrkzHEp0J
	oXToXOEK4OL7KnVLmC5ZIGU=
X-Google-Smtp-Source: AA6agR4C2TL8gKpwGMmk39EFTmUKLmt+mAw7uf0a8Pk4wOYt8qZlfK7l7E1zpG4P6yB+DUuHZAfknA==
X-Received: by 2002:a6b:ba44:0:b0:688:876b:61c6 with SMTP id k65-20020a6bba44000000b00688876b61c6mr14394980iof.51.1662023936161;
        Thu, 01 Sep 2022 02:18:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a183:0:b0:349:e63e:93 with SMTP id n3-20020a02a183000000b00349e63e0093ls334552jah.9.-pod-prod-gmail;
 Thu, 01 Sep 2022 02:18:55 -0700 (PDT)
X-Received: by 2002:a05:6638:3385:b0:339:ea59:a31f with SMTP id h5-20020a056638338500b00339ea59a31fmr15792726jav.55.1662023935712;
        Thu, 01 Sep 2022 02:18:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662023935; cv=none;
        d=google.com; s=arc-20160816;
        b=SBySbmdugv561Ypq2YFCAKBsGGncL9XMFmdTtU2vtltEUtkJArCBgMIZyV0NQnxMQ2
         ZpKqRzr3/WkFQ7M1fYJ/n+d4EICT0OKQ1KWAbpNpsd6iyjQJ/y77kt5MNxsxGpsK3sm1
         5JqfUvGHHx9KUp+xFrJ8UfX2pJ6klRUg5DkFzoX2wiMs7SWTvMdgs1BfunzIlnrL7KWT
         zETVioqKX09J6MffKtdYLc9h0Gh+2N9Ly9udv+xCUitHNjh1lceF1AkXuaMFfFW11cLm
         i31Z92TZdO+aYSd+CZqaH78heSlsw4PCBPtJyQG/hc5tyF2jdzm9KoZwguGSr9hMaO/c
         mIuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ofyTx4HKrXBAG7we5X7Qai/eK2K43C5jxgUz5nh/Yro=;
        b=hNqvE2tVsb2DOfVQPbhPbU8QlioK6wn3oLAMa545GKaqZ1EqWWkCVwA60J3t7rgwys
         37THCCDn0/sK/MbikE7P/pxzGYzNFh7pAA4h/2PCNhG6Hn8qWIpj+Jd08aOY0gkpbgid
         E4wNrDQLED3HntCLM3gOrqd/ghqZiOVghqs/b4iNiSqPvMV432kH5NXuCVLK8b1lhT8l
         vETAQokNrgs2siDkxqY8P3R7WTDbio0OLJboAaQsCgv4YYy5yfXnWAQmG3UMCGEwI5oD
         63tqmTAVVXfK0ybx0jxO2ZGOIuS1q1cM3AS6q8r/3fYx9/UE6P6Zkoy1WNFCfyAImcyS
         LXUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DNWL+HfE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id b18-20020a029a12000000b0034a2ee4c7bdsi562074jal.2.2022.09.01.02.18.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 02:18:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-333a4a5d495so330133207b3.10
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 02:18:55 -0700 (PDT)
X-Received: by 2002:a0d:ea49:0:b0:33d:bce7:25c2 with SMTP id
 t70-20020a0dea49000000b0033dbce725c2mr21912903ywe.267.1662023935298; Thu, 01
 Sep 2022 02:18:55 -0700 (PDT)
MIME-Version: 1.0
References: <20220901044249.4624-1-osalvador@suse.de> <20220901044249.4624-2-osalvador@suse.de>
 <YxBsWu36eqUw03Dy@elver.google.com> <YxBvcDFSsLqn3i87@dhcp22.suse.cz>
In-Reply-To: <YxBvcDFSsLqn3i87@dhcp22.suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 11:18:19 +0200
Message-ID: <CANpmjNNjkgibnBcp7ZOWGC5CcBJ=acgrRKo0cwZG0xOB5OCpLw@mail.gmail.com>
Subject: Re: [PATCH 1/3] lib/stackdepot: Add a refcount field in stack_record
To: Michal Hocko <mhocko@suse.com>
Cc: Oscar Salvador <osalvador@suse.de>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Vlastimil Babka <vbabka@suse.cz>, Eric Dumazet <edumazet@google.com>, Waiman Long <longman@redhat.com>, 
	Suren Baghdasaryan <surenb@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DNWL+HfE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 1 Sept 2022 at 10:38, Michal Hocko <mhocko@suse.com> wrote:
>
> On Thu 01-09-22 10:24:58, Marco Elver wrote:
> > On Thu, Sep 01, 2022 at 06:42AM +0200, Oscar Salvador wrote:
> [...]
> > > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > > index 5ca0d086ef4a..aeb59d3557e2 100644
> > > --- a/lib/stackdepot.c
> > > +++ b/lib/stackdepot.c
> > > @@ -63,6 +63,7 @@ struct stack_record {
> > >     u32 hash;                       /* Hash in the hastable */
> > >     u32 size;                       /* Number of frames in the stack */
> > >     union handle_parts handle;
> > > +   refcount_t count;               /* Number of the same repeated stacks */
> >
> > This will increase stack_record size for every user, even if they don't
> > care about the count.
>
> Couldn't this be used for garbage collection?

Only if we can precisely figure out at which point a stack is no
longer going to be needed.

But more realistically, stack depot was designed to be simple. Right
now it can allocate new stacks (from an internal pool), but giving the
memory back to that pool isn't supported. Doing garbage collection
would effectively be a redesign of stack depot. And for the purpose
for which stack depot was designed (debugging tools), memory has never
been an issue (note that stack depot also has a fixed upper bound on
memory usage).

We had talked (in the context of KASAN) about bounded stack storage,
but the preferred solution is usually a cache-based design which
allows evictions (in the simplest case a ring buffer), because
figuring out (and relying on) where precisely a stack will
definitively no longer be required in bug reports is complex and does
not guarantee the required bound on memory usage. Andrey has done the
work on this for tag-based KASAN modes:
https://lore.kernel.org/all/cover.1658189199.git.andreyknvl@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNjkgibnBcp7ZOWGC5CcBJ%3DacgrRKo0cwZG0xOB5OCpLw%40mail.gmail.com.
