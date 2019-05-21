Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVWESDTQKGQEX56DMBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A8558254E2
	for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2019 18:07:51 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id c16sf14498602ioo.20
        for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2019 09:07:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558454870; cv=pass;
        d=google.com; s=arc-20160816;
        b=XNE1GNSH52++e4n8WqkTRbbk1nJpKLaI8WlcepXPnkmqTCObkNzSx3x6VInuinNwqy
         bop8HElanwTmwxtwswD5rto206atLHlyOMaGYT4T3fseCwXwpKPO+U49kzVjb+B7SRB3
         5RYL3uz8MtH3hxmg4q4UEDB2YGWde8lfmxfM36OnDDoZlC5JdI+9Zp4gf+uuhlXehWl4
         M/PA+VJJFMrBvFKjfWBhyD25Z7LKnWBunhB4YDyqF7FNVycb51IT2yb+5lYGeF5xAAvJ
         fN+O8X0ATOgl5FAH1XdSwKSV+sy/7mi3yjHWJKlmqoVqhqoXl8j8kAcHyqhd9tgv3rv+
         QljA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xM/t2nbNkHEg63b9m43E6/ol2jofndkhDMVapC+Pbv4=;
        b=PmnKnDcrn3FHyA78IuLuSAjW4oYOL46OSsnmq9J1+Ah8zvBWqVSbO0juafLRs3GojK
         YpdILH1S2rXbLbZ7JObj9itCNwk3EcabdL3fEzDY0A1TGwg4uZ4fkpEEVicQqsUl18Jh
         RGLr1fhPOfjkLOS8+KDRktGiMjDNToGJrmXNl8+IUbydGtyo1dKVFRrJ8rJU4U6vqDbK
         KLTa6bQVKOO4JQx5zfsVFzT3NrfPUxuKB+LgBoQ7kQcdaGW1asJg9rgnWYL2FanU1kkY
         TZdGDdKfWLbZ8oHT3R2sic6afq/z4PHtC0XBitzIkLEFfYIDpCuHhWfMbysh7ksbwlZz
         Zizg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SslTEkbd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xM/t2nbNkHEg63b9m43E6/ol2jofndkhDMVapC+Pbv4=;
        b=e6PBP48ymmQtnq1Yy7Kqe7hDBitYpRiMO46OsvqW8dZKvpCMZK1BII29d/672aZbkg
         C+2rlhK3tI9iYGH73tfcbpQ5E5Ida49LKH6tMWLM7umTf0sCDkBqSyTKhDQovX5VCOa/
         8GSe7sq5ORZU8TTp0WphvhFjWsS3qZ+Zydu0ZBZjKb6zifljK3ex0y3GmmpXLEf1u6GK
         EGTdJZL6HnXgzuStOZOIsGEYsOLmgTN1OL3wTIxNm2G0hhmniaeFQzF9CEsOZa1UFGiB
         k085pkfzbeIdjQE1eaWebkxv+nwmbrYgWY6WAULDv8dLs98mxFA4dAmIqJFr0xvsv+L3
         wyTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xM/t2nbNkHEg63b9m43E6/ol2jofndkhDMVapC+Pbv4=;
        b=I6Fz3trhKKaPCD80Dvq2ba4gm7J3zUsgNHfEUp4gshmO0QvI7ugGON6ZnoBXRb5vr4
         W70G8BdsfX8Wev0AYoKy0U/gIVv0aGZHLO+yLzAZyrsKW5a/U0BOm9akZN6vXn8nYg5k
         XARYOx1x3LK6qij3MMZuA8QikzO76BrzvZd0lV/Hdnsa9FerevjXmt+OpVsFtxbx0Ch4
         unaPveTPzhLh+/Q0eupNbbNFZLMaPZ5Piby3PIcESv0B/myw13i4jPIx+ZlkZop7wfoQ
         Bjjhcwv/2hBJJhjHoL9KzbWOvRJGKk/47HavER1SNsL53sVmDGBMz5VVVTZr+OfdOPgM
         I+iw==
X-Gm-Message-State: APjAAAXjQ6zj0ZoiwJPUTQXOznikASNU/IbkI3NaLaDpO3XjyhVpdp7T
	udrdKAQ4cEB//pW/jz02rgE=
X-Google-Smtp-Source: APXvYqyjt9rzVqAQmssRPwevL+G3X79bxvp0MWlhUMGVzfEvpJ82s8wexJUSMQhzOGw/O4xWsXTxyw==
X-Received: by 2002:a24:fc46:: with SMTP id b67mr4534234ith.4.1558454870330;
        Tue, 21 May 2019 09:07:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a24:a01:: with SMTP id 1ls1089967itw.3.gmail; Tue, 21 May
 2019 09:07:50 -0700 (PDT)
X-Received: by 2002:a24:4313:: with SMTP id s19mr4885604itb.126.1558454869999;
        Tue, 21 May 2019 09:07:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558454869; cv=none;
        d=google.com; s=arc-20160816;
        b=cl3wnd8y0lWRp4adA04LEMipzGFq+UI5FyVdo9X01Il/PFgAuEXLCXfqleHOOcFnU1
         dBtjs7Huu2FOM8z1PevectwoZeDMbYMGPRnBtzi2nCNl1pSL/jlu5XsSEo+wOgJLVzo1
         p6zQVHg679GbUiKRreL99qXLKE0iIksc0lLclTREV5PcaEvnm6MZ/fFHhbPSrs7Ktmnw
         7QZoSiFCFY7RnsS/8siig7KbP45GO8DC9GFExAhB6dImFONho5aUm5Hv3w6d3lcoG3NU
         87BMBAt5E1Yc936Pc1MYGg946CxLc2sEDqfF1hCW7co9PY7rUCRjcyVLqER9JuYvkd2s
         PKCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z6DwY5PU6T6VLE2Cxc9SEtMv6vL/0lIxHi6A4Ph2gaM=;
        b=QhTxFASDBbHBVPzXocCotaOXMJzjYqpwp7pj196ES0xv/k3YqNNkqxSF6taRlknK9x
         3Ks9JSzsCFmBqw2+qHrWiKcEDWlT2KYLXA52n61WYf20DM7c0zXwQMdylPcLyKx5ypqP
         fcaDGzyJy8tM5EnpTmyeH6wL2/qSSWKAKDL8WvvVXhbNmBvKnocyzl7Fhwt1jTuDGgF4
         10KV5c6cVeycz1YEaLw/D6EvJrJxypTYXoLRDhsMKGPjAIbHLfPzA8i4eIW8VvYgtOZ0
         YebP80OYZSheVBmZZxf0uHWlg0mkRpUAJZ1Ie8ew1sCPS9X4u3Qkv4OVLmj8CQtMgC0u
         /3Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SslTEkbd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id n74si122754itn.0.2019.05.21.09.07.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 May 2019 09:07:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id s19so16844975otq.5
        for <kasan-dev@googlegroups.com>; Tue, 21 May 2019 09:07:49 -0700 (PDT)
X-Received: by 2002:a9d:362:: with SMTP id 89mr6331724otv.17.1558454869448;
 Tue, 21 May 2019 09:07:49 -0700 (PDT)
MIME-Version: 1.0
References: <20190520154751.84763-1-elver@google.com> <ebec4325-f91b-b392-55ed-95dbd36bbb8e@virtuozzo.com>
 <CAG_fn=W+_Ft=g06wtOBgKnpD4UswE_XMXd61jw5ekOH_zeUVOQ@mail.gmail.com>
In-Reply-To: <CAG_fn=W+_Ft=g06wtOBgKnpD4UswE_XMXd61jw5ekOH_zeUVOQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 May 2019 18:07:37 +0200
Message-ID: <CANpmjNN177XBadNfoSmizQF7uZV61PNPQSftT7hPdc3HmdzSjA@mail.gmail.com>
Subject: Re: [PATCH v2] mm/kasan: Print frame description for stack bugs
To: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SslTEkbd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Tue, 21 May 2019 at 17:53, Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, May 21, 2019 at 5:43 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
> >
> > On 5/20/19 6:47 PM, Marco Elver wrote:
> >
> > > +static void print_decoded_frame_descr(const char *frame_descr)
> > > +{
> > > +     /*
> > > +      * We need to parse the following string:
> > > +      *    "n alloc_1 alloc_2 ... alloc_n"
> > > +      * where alloc_i looks like
> > > +      *    "offset size len name"
> > > +      * or "offset size len name:line".
> > > +      */
> > > +
> > > +     char token[64];
> > > +     unsigned long num_objects;
> > > +
> > > +     if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> > > +                               &num_objects))
> > > +             return;
> > > +
> > > +     pr_err("\n");
> > > +     pr_err("this frame has %lu %s:\n", num_objects,
> > > +            num_objects == 1 ? "object" : "objects");
> > > +
> > > +     while (num_objects--) {
> > > +             unsigned long offset;
> > > +             unsigned long size;
> > > +
> > > +             /* access offset */
> > > +             if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> > > +                                       &offset))
> > > +                     return;
> > > +             /* access size */
> > > +             if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> > > +                                       &size))
> > > +                     return;
> > > +             /* name length (unused) */
> > > +             if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
> > > +                     return;
> > > +             /* object name */
> > > +             if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> > > +                                       NULL))
> > > +                     return;
> > > +
> > > +             /* Strip line number, if it exists. */
> >
> >    Why?

The filename is not included, and I don't think it adds much in terms
of ability to debug; nor is the line number included with all
descriptions. I think, the added complexity of separating the line
number and parsing is not worthwhile here. Alternatively, I could not
pay attention to the line number at all, and leave it as is -- in that
case, some variable names will display as "foo:123".

> >
> > > +             strreplace(token, ':', '\0');
> > > +
> >
> > ...
> >
> > > +
> > > +     aligned_addr = round_down((unsigned long)addr, sizeof(long));
> > > +     mem_ptr = round_down(aligned_addr, KASAN_SHADOW_SCALE_SIZE);
> > > +     shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
> > > +     shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
> > > +
> > > +     while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
> > > +             shadow_ptr--;
> > > +             mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
> > > +     }
> > > +
> > > +     while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
> > > +             shadow_ptr--;
> > > +             mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
> > > +     }
> > > +
> >
> > I suppose this won't work if stack grows up, which is fine because it grows up only on parisc arch.
> > But "BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROUWSUP))" somewhere wouldn't hurt.
> Note that KASAN was broken on parisc from day 1 because of other
> assumptions on the stack growth direction hardcoded into KASAN
> (e.g. __kasan_unpoison_stack() and __asan_allocas_unpoison()).
> So maybe this BUILD_BUG_ON can be added in a separate patch as it's
> not specific to what Marco is doing here?

Happy to send a follow-up patch, or add here. Let me know what you prefer.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN177XBadNfoSmizQF7uZV61PNPQSftT7hPdc3HmdzSjA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
