Return-Path: <kasan-dev+bncBDW2JDUY5AORB27UTKKAMGQEH277IGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BBFC52DF86
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 23:45:17 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id u8-20020a170903124800b0015195a5826csf3130254plh.4
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 14:45:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652996716; cv=pass;
        d=google.com; s=arc-20160816;
        b=XdPvX1DpvqG9IASLRfEUW4hPEcLreMJE9k3HuhMuFS5rEdHc7KjK+DXrlJCQUyzcNX
         hNvpBvlZuiYp2z/dhKKXWW3JvuRpG1lj8ros3hWW9AOi7EqAP0dnkQ42edUjN9OLIhJq
         sAE0jMtIqrkMdKMFOyrrnJpzkstNCTxRj8i1muIibDUthY7n8JjXZtkhyWTyIjEbOpoU
         8Nuj1OM6J7hy5IkQ1rotcvB84lQcNsxa44549NsC5iaekr8++Ntb+wym/DSM8lDNZhpl
         jsqAmKU9Ux6RGzlepTksW1AIzQjuMWCafJMKgun9NSsym45cfsP7hNeiw5g2fHJZHjkq
         5LwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=A9s+9JXjQduGp2uIXMPGdVrvwEIwBuX/glGJAaySdBI=;
        b=II5FWZJo8PWZDgfkLGwYUHXosj42eKcH+2jJjq7t3ThsSexNQHm6v67M7pm38c1LpH
         8ET1Sa5Ysp6smgRiBL6xzsfEmKESmQ5FbcWYGyN1Y4X3mkofBpdYl4Wl4SLu4xViJMlI
         x6qGLQE54qWGY8GKW9AEaw6h0EH4CTimVAECjQA3CXR1r5+evp9c/+CAB+aw9EBsJ9ku
         SdTvHJoKDD5KpBmevXWkRCRKJwULFl6ndkN1wfx+JLQar2V80sPstrr/CymyEyjpk9/z
         eiFX+Q2pv9VOt1DDAaq6nRA292o1xp1WZ/j/BSVzg0PGs0dobEujrvsTCsG/Zfta6uJa
         pYEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QbGfoRXM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A9s+9JXjQduGp2uIXMPGdVrvwEIwBuX/glGJAaySdBI=;
        b=DpBmoM0F5PTCCVYgHDF5HPmkDFjpHdf2wQComn+85DTBuu2lppYdn2WtnTflTBkhZa
         i5MA5O/XPTuLly99OTAWB4TPKgrbwbgi1hNRi/HQ1zKf7C3QloE+tdVt2iadmr8qIPHA
         VdflI2LuULzR1lzihkBMwZdpStpFAgBkFAV25j1vV3m8jqCM2eEqCb4t2Im5n/HLxNlI
         jnvr9z+D3dKzQWxTe9nDmlWj3Qd7z7rX/gJPVo5SUe1deOaWoWEMhJcpHr9JVhbcBZBt
         WMYDu3bNniJChBARxvQMfhagvkqY5/gLQavRS/nNezcYIzjihdv1PfMH1yFANgI3Hi9h
         PGtA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A9s+9JXjQduGp2uIXMPGdVrvwEIwBuX/glGJAaySdBI=;
        b=b4T6iKKxg/WyobDDHZq+t5lWapwfN8YbnSib5mQYwBx43+RpplSU0yfCqqODwq5+ub
         aL/Enj92X2M0BRc2UcDU1VySlIY0Br3Oh43pa6A/dQUkJgyqh/ZrtRxx9oH40nUZf+U5
         EQVZI5UeTas7WnE2cg5MXBNwq3fD4uQIMLKtK/41JlxJ/w/MXPiOSBhcsBFbhhzp8ga4
         L2qOvXHa4Hq+xGEUFf8q1IlbVBChce7lTeXdxBUg5LJuXnO16xHwfudG6VUBfHVWV47f
         h8E4hSLzOUxHcY+EwRRwm0an28+7OUBJzMRXD3EEA4Oih501SIfVOeC9eU4erolPNZFT
         /EeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A9s+9JXjQduGp2uIXMPGdVrvwEIwBuX/glGJAaySdBI=;
        b=IlDT0BUuWlDkYqZOyla45Ld83QdltR0lPp3SurLeCOlYgaPz0zMiyCIF57j9GhSGbe
         Bd2RWolhRkYHm+WJoJpG8UwZq73Fn9wz+T37ohOZnJao3VzWn/l7FzEWXnvaOR5DghOn
         Q8RfAw0U8JJNIs3hr3FE7/ATzXvPsLvDXRD/v09ph6hCPY9YVYEuxrxF0wwB/g5ZvfX3
         yKHpL9GLq98TIyrlEWDduAHm+pzRK1751XEWUCBO5w6nh07F0XyrOo8MGjhUllQDUxX6
         04JKpDpLB77FDwxjp3lz8dzJj5jz+HkG/cFj+9dur22jAqcF+knJN1b0ZtY55mZhM+PL
         gkDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DgMEXoW4VRYLmyuCUBWL2OeviuQB6kXRxJ4eOlXrH4bCaNGwi
	WSpKu289TSIaagem/pZzFBQ=
X-Google-Smtp-Source: ABdhPJykn6iTKSVgYD0ZI6iFzDd33XHdgGlnz5/pJNbqJGxLsRh6zQXBiwz8E543ngkbty9rX2Topw==
X-Received: by 2002:a17:90b:1b44:b0:1dc:315f:4510 with SMTP id nv4-20020a17090b1b4400b001dc315f4510mr7880270pjb.28.1652996715955;
        Thu, 19 May 2022 14:45:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5a81:b0:1dc:e81d:6bb1 with SMTP id
 n1-20020a17090a5a8100b001dce81d6bb1ls2669565pji.0.gmail; Thu, 19 May 2022
 14:45:15 -0700 (PDT)
X-Received: by 2002:a17:90b:788:b0:1df:5ffe:ad15 with SMTP id l8-20020a17090b078800b001df5ffead15mr7853905pjz.141.1652996715272;
        Thu, 19 May 2022 14:45:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652996715; cv=none;
        d=google.com; s=arc-20160816;
        b=WT0VFEk8zcbZyrE5dG3zxp/Ee0BJ2lJu+yAcqkEDSpqubCZT+mZsHixdVF5vfxMCfr
         43qS8TUUlGnufHAIKxM4b5FnEKZ9Q11j6N23vDuVEdGfOLdRdCcmVOd6kMAfTjRYtBNR
         eRHWrLOqz9Yy44hUEKzhC/x5ei861gtmXJs1kQDBpRKrecmJoL8MTrfQotI77AGgbFv7
         VzuPW4vg5eD1ZjQs3JegJjAV2WZRuaXA3OgkiDotaOuuxYjwq1r9xEI68qk9OgrFk82A
         jtG0Ot3u/bKgUUnqmaofqhimHQzji5qUc6+SIBA4VlUtxZTNBCOg1Y83WCoRzfzUaO2R
         zcwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=my9je9EYZl7JVeMs/i+hH21WjUx7K+0NW3mXQ84nNhM=;
        b=Ogg10x44dKBzPRQ5jICa/wayzsSX0tgCSJp+KzRSMjR717xbFO9A5paFBlpT/h7ISd
         h4jg8Z70/AOUKpAV/Oa7XpRgEA6tQvKQWojBUTvCJoWwNFJEA5opKn3lx+BKg60WmXi3
         7RZxrdmi2efFY16nFnRL0nOK4pOtWQBhc8v1asBkOsMK9aoGotYk4XBxwTPvsa3Y+Y7U
         Clyvs2Va6xXT4VfywzUTiaf+0csruoRtIcaVbHg0xwoFk72qazf3TEnZ2bnDud1cDENl
         An+Iz/v/TwvP/w2ZVjI6x4ejrdmKWqh4ufljKW94zrwKkESq/Lrj8lImTO2sVSPAN5XU
         uppQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QbGfoRXM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x135.google.com (mail-il1-x135.google.com. [2607:f8b0:4864:20::135])
        by gmr-mx.google.com with ESMTPS id ja3-20020a170902efc300b00156542d2adbsi240855plb.13.2022.05.19.14.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 May 2022 14:45:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) client-ip=2607:f8b0:4864:20::135;
Received: by mail-il1-x135.google.com with SMTP id f9so4511325ils.7
        for <kasan-dev@googlegroups.com>; Thu, 19 May 2022 14:45:15 -0700 (PDT)
X-Received: by 2002:a05:6e02:1c2c:b0:2cf:ef3:f4df with SMTP id
 m12-20020a056e021c2c00b002cf0ef3f4dfmr3705269ilh.235.1652996714967; Thu, 19
 May 2022 14:45:14 -0700 (PDT)
MIME-Version: 1.0
References: <20220517180945.756303-1-catalin.marinas@arm.com>
In-Reply-To: <20220517180945.756303-1-catalin.marinas@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 19 May 2022 23:45:04 +0200
Message-ID: <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com>
Subject: Re: [PATCH 0/3] kasan: Fix ordering between MTE tag colouring and page->flags
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=QbGfoRXM;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Tue, May 17, 2022 at 8:09 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> Hi,

Hi Catalin,

> That's more of an RFC to get a discussion started. I plan to eventually
> apply the third patch reverting the page_kasan_tag_reset() calls under
> arch/arm64 since they don't cover all cases (the race is rare and we
> haven't hit anything yet but it's possible).
>
> On a system with MTE and KASAN_HW_TAGS enabled, when a page is allocated
> kasan_unpoison_pages() sets a random tag and saves it in page->flags so
> that page_to_virt() re-creates the correct tagged pointer. We need to
> ensure that the in-memory tags are visible before setting the
> page->flags:
>
> P0 (__kasan_unpoison_range):    P1 (access via virt_to_page):
>   Wtags=x                         Rflags=x
>     |                               |
>     | DMB                           | address dependency
>     V                               V
>   Wflags=x                        Rtags=x

This is confusing: the paragraph mentions page_to_virt() and the
diagram - virt_to_page(). I assume it should be page_to_virt().

alloc_pages(), which calls kasan_unpoison_pages(), has to return
before page_to_virt() can be called. So they only can race if the tags
don't get propagated to memory before alloc_pages() returns, right?
This is why you say that the race is rare?

> The first patch changes the order of page unpoisoning with the tag
> storing in page->flags. page_kasan_tag_set() has the right barriers
> through try_cmpxchg().

[...]

> If such page is mapped in user-space with PROT_MTE, the architecture
> code will set the tag to 0 and a subsequent page_to_virt() dereference
> will fault. We currently try to fix this by resetting the tag in
> page->flags so that it is 0xff (match-all, not faulting). However,
> setting the tags and flags can race with another CPU reading the flags
> (page_to_virt()) and barriers can't help, e.g.:
>
> P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
>                                   Rflags!=0xff
>   Wflags=0xff
>   DMB (doesn't help)
>   Wtags=0
>                                   Rtags=0   // fault

So this change, effectively, makes the tag in page->flags for GFP_USER
pages to be reset at allocation time. And the current approach of
resetting the tag when the kernel is about to access these pages is
not good because: 1. it's inconvenient to track all places where this
should be done and 2. the tag reset can race with page_to_virt() even
with patch #1 applied. Is my understanding correct?

This will reset the tags for all kinds of GFP_USER allocations, not
only for the ones intended for MAP_ANONYMOUS and RAM-based file
mappings, for which userspace can set tags, right? This will thus
weaken in-kernel MTE for pages whose tags can't even be set by
userspace. Is there a way to deal with this?

> Since clearing the flags in the arch code doesn't work, try to do this
> at page allocation time by a new flag added to GFP_USER. Could we
> instead add __GFP_SKIP_KASAN_UNPOISON rather than a new flag?

Why do we need a new flag? Can we just check & GFP_USER instead?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q%40mail.gmail.com.
