Return-Path: <kasan-dev+bncBDW2JDUY5AORBJHT3WCQMGQEKPG5OGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4339B398988
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Jun 2021 14:29:25 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id r1-20020a05600c35c1b029018ec2043223sf543943wmq.7
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Jun 2021 05:29:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622636965; cv=pass;
        d=google.com; s=arc-20160816;
        b=YkhZtp27erYN6UsZMCYNBJH4TIQ2IjIa6+N6/EaxvOsGWh6catdGu/uri095IyJt9a
         nNs3Dt/zs03HRDJ9qy16Cy/3pxVgMwIXUK4CSXl/vzSxgC9W+pI5cItutx+/shvvJovY
         VPSZjJ/TQIgIL07YG7CV0klbrT2CvKzINisc4J1v2pwLK+5ql0gn9qM+1mfTHVNJZETN
         zjt7XRJwiCPWmBJLtNh2eaa7QWeOjlfYAMLKR12nQaSeDC2BjsQ9AxkUSkKe+T8GteAC
         OA2Fj4U1XUmoVouu9eU+M61b/pp7LaBNU8/a7a7mTx/YK8X/GaVclrNzeK5BN/atc1py
         G8Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=yakWu5M1qJKTaJW5Ouz9MlnrLgpbvlfuiQT0RgnDTjU=;
        b=Hve7Ck5tmuznFHF5wrWKkNZ4igWXptlwLVAiGBjHsGHcIjMCot7Iqx9tbJgqa/a3yi
         eQYpWc4kSkrLD/ec/7DsKJcX0yN77ckZni3PZJ+NRD+V84afT3jKNc1/KL9jDzVdiyBk
         m7CZiWANNStInxuG8D2RuhrsUbIQwtjzZ59Y3J9vFfPeyU3L1k4VYphZvIlUcvoiFJbs
         4wzg6yFAM4TFgAlhd0VUNNGxP2RoWtxGoEyDgBP7yGYBSZf2Ig23IOXkeKe0EqT0DJUH
         11IPDhik8XOhW71P02XJjIF/PDerwLyKYYQDP1GFXpF37YZXgAFdBvY2PkseXyTuyWoX
         YotA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oR1MekKq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yakWu5M1qJKTaJW5Ouz9MlnrLgpbvlfuiQT0RgnDTjU=;
        b=flBJBmUaVTMy710vSzuXZIWo7pvwXRE9hMvdflSLXf3rJGjyu06uO4u85d3sRYEP9j
         3KTOPprzDIVlDbyKKXhV+Gremo1yxVPQB243TKbX3l4rF2K3M91GFtG6vfqCAE5e4hEQ
         ppx1kvZg5SOHknQa6pRw2MeFFgfacFBbUe/Su05K7D0Y0am8jpkABgb2CUWKPJNys+XD
         zYzAoO5d3PEEC5leTA+L+LozLDXlZ7DJI+wiw/M4jT38/DbRue/LVCcblAAbt0512uag
         2zbMDMwXR18dqjeTcTEMxatR3SpsZTpl/ySGXB8TJXIsV535TQa8w69GXhYZGm8PVF9Z
         yHxg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yakWu5M1qJKTaJW5Ouz9MlnrLgpbvlfuiQT0RgnDTjU=;
        b=oRiA+BUPmcbffM5U/sKDp6F9zTG0dI1hd6Jq697n/0y8/B96q65+HFpEjNf0LppMVX
         vudjUa1bLger6tXoO1dccC8lQHOPZgKHPL6hLNa2kI4iZUrQGj4c3mVssAkp4SNHNmPw
         4qtDro+PWncLhBkMEecIngmLawfh9Vf//ngxUeml7BJ+ywH6yXoYSjYFOvH56+U2FzCJ
         RhZ39WwqkgUsPlkP9bi88mtEJ2bUDgQ1ks3E2NuM65Wl4zsyHSm2MNAh47IwcYTkSn3T
         pVCS027w/bKDyxUdb8MNpVPGqASXZqlS3rj0Xh9KQVemJ85qE4pVZP6vcYQpFpTCshro
         L1Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yakWu5M1qJKTaJW5Ouz9MlnrLgpbvlfuiQT0RgnDTjU=;
        b=Zbc9uGExytZlOnguyNWfP+w4rFwmbLSAi4FXO61i+RGHKj6+twgL09VCwS4AcW1AAl
         tnRlIrD13OkljuwziybRDQFfFUcKOC9y/fCqwGJbexnL91FykWN+7uTqiufbaRRtwMvQ
         XSIpAyuSqNEKTRz0ipNrTy6jmpuwYsN0a5hVWXEjSa4L1MeBTi7BTUWdQWPYvySpvu6O
         6uNyVBqZK5X1Z+9dHDhlaGJ44Yikrs63S1Gg+OvO7YheoRk7YbNA7m/JrM6zL6Jd7uTJ
         +4EP6clecHtQI66QpSHLl1tLv58HnpzzXLWQx2ZqFJHaoejjhoWNpWVDlUDYjGM1emw3
         CEeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530p8FSBwgZy2Oz6ilbXDJwyTHg/iHjp4z0hkpGgcB8ntB5arWRx
	ff8aZeBQ5WS1TFcuAbVq0PQ=
X-Google-Smtp-Source: ABdhPJw3D/uDHgjURDs0x2ZudlSFqpidJZl867OYWTuEXZ/I6OgzUgFC0XVRscK00D1A4A9xB3+YKg==
X-Received: by 2002:adf:df8a:: with SMTP id z10mr5466998wrl.62.1622636964969;
        Wed, 02 Jun 2021 05:29:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f52:: with SMTP id m18ls3226854wmq.0.canary-gmail;
 Wed, 02 Jun 2021 05:29:24 -0700 (PDT)
X-Received: by 2002:a1c:e10b:: with SMTP id y11mr13543537wmg.45.1622636964214;
        Wed, 02 Jun 2021 05:29:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622636964; cv=none;
        d=google.com; s=arc-20160816;
        b=OdTjThAIaCXPpLx02/LwChg7+tHnWEhkid6ZvHexBWHXkB2G9YbIEqPTXY1AXeuXV6
         4GIx71wEDgR+2Pyg5JZ9jms7UWjLQxIHTXI2gEyLAfzHZR6QOiNeQ4Pw4HbDi4fqpOki
         zkpizwKtZk9HfNCS2T0hLZ2ufOUr5op43j0mOLI6awH2uJU72CFSmtbImaRHWZfs+IO9
         CYtu6X5bpdcvglevSmO6z0VXnRx0Q80zuaho7d7odTXoBn5VF5AnJpCc1xXbbWlgU9Hf
         M+rf0j6mjIk5yUc0SgUY6GXbHei49cEI25tjLo3JiNc94PAG3Ft0hUt3mRZKqPxUvw1X
         PRkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FgEY4csnfMiTaVbU1WFo7uBvyH/cKykPw3Skdbt2rUs=;
        b=zPciKcH+ioPvEjCi4GRjbTmKnm+aR6VYxVz5Q3/03aib9X50YJPaENNCZ17TKCaY8I
         fFTT6hIOjc3gksf6HPML7qTv2N4HwW7ZiOc6eVPe7EGSOSkwqQK8DkkOL9WgkXQSYFSJ
         n29tdT8YhzQIYn7Iapsj6OqR+3bsF654ipyaJXvdsSnURJkEF8QymTj+D3BmtJPLWM21
         e6kRZzPmF9P/8NUbojCW2tgiLb1msexfaQHVrSGT2euNqkspn4Dom9l9zov8zO+JJ3Fj
         aOzMiM9vkr71j4IJKHqaSz+7p9HhQevOSm6GhfAHQf31JI27FiVhAUP4fuA+ACGVNvDo
         Lqqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oR1MekKq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id s9si150691wmh.1.2021.06.02.05.29.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Jun 2021 05:29:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id r11so2655749edt.13
        for <kasan-dev@googlegroups.com>; Wed, 02 Jun 2021 05:29:24 -0700 (PDT)
X-Received: by 2002:aa7:d74b:: with SMTP id a11mr1480803eds.95.1622636964034;
 Wed, 02 Jun 2021 05:29:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210530044708.7155-1-kylee0686026@gmail.com> <20210530044708.7155-2-kylee0686026@gmail.com>
 <YLSjUOVo5c+gTbzA@elver.google.com> <20210531155912.GC622@DESKTOP-PJLD54P.localdomain>
In-Reply-To: <20210531155912.GC622@DESKTOP-PJLD54P.localdomain>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 2 Jun 2021 15:29:12 +0300
Message-ID: <CA+fCnZeXEiTi-k4_XkYTvE2mQcXvP0Ct1N5VDEFfPufFqz15+Q@mail.gmail.com>
Subject: Re: [PATCH 1/1] kasan: add memory corruption identification for
 hardware tag-based mode
To: Kuan-Ying Lee <kylee0686026@gmail.com>
Cc: Marco Elver <elver@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Walter Wu <walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=oR1MekKq;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536
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

On Mon, May 31, 2021 at 6:59 PM Kuan-Ying Lee <kylee0686026@gmail.com> wrote:
>
> > >
> > > +config KASAN_HW_TAGS_IDENTIFY
> > > +   bool "Enable memory corruption identification"
> > > +   depends on KASAN_HW_TAGS
> > > +   help
> > > +     This option enables best-effort identification of bug type
> > > +     (use-after-free or out-of-bounds) at the cost of increased
> > > +     memory consumption.
> >
> > Can we rename KASAN_SW_TAGS_IDENTIFY -> KASAN_TAGS_IDENTIFY in a
> > separate patch and then use that?
> >
> > Or do we have a problem renaming this options if there are existing
> > users of it?

Using the single KASAN_TAGS_IDENTIFY config option is what I would like to see.

Since this is a purely debugging feature for a less popular KASAN
mode, I think renaming the config name is OK.

> I tend to keep KASAN_SW_TAGS_IDENTIFY and KASAN_HW_TAGS_IDENTIFY
> separately.
>
> We need these two configs to decide how many stacks we will store.

You can define KASAN_NR_FREE_STACKS to different values depending on
whether HW_TAGS or SW_TAGS is in use. I don't see a problem here.

> If we store as many stacks as SW tag-based kasan does(5 stacks), we might
> mistake out-of-bound issues for use-after-free sometime. Becuase HW
> tag-based kasan only has 16 kinds of tags. When Out-of-bound issues happened, it might
> find the same tag in the stack we just stored and mistake happened.
> There is high probability that this mistake will happen.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeXEiTi-k4_XkYTvE2mQcXvP0Ct1N5VDEFfPufFqz15%2BQ%40mail.gmail.com.
