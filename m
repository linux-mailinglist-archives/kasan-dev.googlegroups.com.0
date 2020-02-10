Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ5GQXZAKGQEWOJO7GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 76212157728
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 13:58:16 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id g11sf5671624ybc.10
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 04:58:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581339495; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ep4cmu+AAoYbeDLjFYfDaEbzeVDQjWQvsHpkvQRhSobXdVNxmx1vt2sKojBJ1iRmNq
         bO0sbT0hD7zOHr7Z8QV9mpg4S9OJY+lNnEZLbeJpbKN7LxIehLYeD4F5gBje6awE2ld3
         4/gxnpX4ty+DGlet1SoyhSKkhEuebHI5yizGB6Mv38bXixC85HnV54UIOCx+sQcOOa0J
         hPj6ablcG4e5d0nsxDd+utGU56PeZ+g4/b2V6VQnqWt1JvtlKZP/891QjeR7kdA1/x/4
         E5wR7sXzD3z4isN+ARxp9mqsBkwLippRw6u3kK9DLGAhD0L2VZkjLi2dyVWIJYp1Hi6K
         Z0+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yXBtwTkCxDHl3forwp08CdangMG2ySHIvaGIA0f12j4=;
        b=TPKal8geLQT7cj2gRAhJZkY5RfIVTUeWD/Wf86pYC6RTFXvVzGt7lk8UvvJt8OdQ3s
         Y56zv8eKSPYNeUYkbomKXwHR9FRe7Xq4Q06F31OtBlp8VOjxZqWJM09oZALxc05ZH4ID
         ZGF8Y9YSqVcyNvE0ans4Hd3Env+kx13Ma4+5PhoYkynYc7cNe1+BhRHTRDVXBg8VOsAN
         GejkVN8FP0weUoWW6/xaAov+y7LSFysGXS3RakM0UuEhw/wGA+uO/Feh8POjyio3gRBt
         eAXWb4HhuUjIkitaq+9GdGGKJS2Av4smNDxTb3jR4MY4w+Dwy9FN1xPVLrXIR1vGf08w
         fgVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aB2mqO0I;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yXBtwTkCxDHl3forwp08CdangMG2ySHIvaGIA0f12j4=;
        b=AHjYW25UlbDLYGQYLzwNUG2tc8qGw3d96LrpBGcTnid5okOnzRA7+W53VBmUwcDPOT
         ab7UK5EbZiOwdF5kCFi0sgpYVyGCJqvlsUjDFvn6Bzty4CWZWKUFTPr+7NLU9pji6vYY
         MVMFvBNas8z09uHjk7bCb444kZfVYXo3nRx5J7LHV/zBE5CFgVQkVIasj80DA5wEMOUS
         KDxNqUMwUhTRDtdhoMcg09m8UlgxZ+1J5sjBKEH9zPJTVS0n5fHDzFsKFBxvUQUyGU2D
         jAG43c+BwLwo2ZsDIV7hHQEgzOA1Q8oBZzPpjtRfEhKSC8nQfaw/0fgipkWw9HdVu1oT
         8sIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yXBtwTkCxDHl3forwp08CdangMG2ySHIvaGIA0f12j4=;
        b=MXntJqm4v6ah1YBA4Eq1plinq6noGRN6j0rBm2OdPwEbeTQipuTIuFxSV6nMBKXd7o
         qWXMzf8QhFaYX5OW+nR9CED+lF2bDXT31mf2E8EEP8lbVTieFgdZO7YH1kJWbCaRU9ye
         kEB7jC9KsmXYHZcEzp/15nJSFOeeiiNXRpvWPRy3dKyO9q4o+jqO4yIREnrzubST827e
         GurGYFQB6rP0NL3frcatRy9xPODThhHueP+oiDBoEKdkN26Q2Abpx0uaM9To/RPSdWqQ
         CGhbRB9nZY4CpM9Vt2Z/J45+TfgZYnR7TsXYffgSRagkaBMnwI1d8WO7sM1cmqS5Reqo
         VPww==
X-Gm-Message-State: APjAAAXdkaprls51h8Sq+E1D0uJxNzO08ToXC6m/GCZ24dsBV2PYctYg
	hJA9ypgLN/eyQ73BufW16zs=
X-Google-Smtp-Source: APXvYqy6GRoz5FHN5YNuAZeIrIReRlSSk2EKxr2RSxL81KvI/hCvheZsdymSeWQSDTES3D1JRcZyDg==
X-Received: by 2002:a5b:747:: with SMTP id s7mr1180259ybq.521.1581339495171;
        Mon, 10 Feb 2020 04:58:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bd4a:: with SMTP id p10ls1534783ybm.4.gmail; Mon, 10 Feb
 2020 04:58:14 -0800 (PST)
X-Received: by 2002:a25:ba89:: with SMTP id s9mr1142431ybg.265.1581339494755;
        Mon, 10 Feb 2020 04:58:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581339494; cv=none;
        d=google.com; s=arc-20160816;
        b=T0YfFDpKlU0Uge/CfnbLQnCubqPDDPIlNTYkKvXfEen4VjWOuolHYSc341PgDn38RN
         bacCuaOE+XLnOfC1CraXKiCVJ0cfXVn3Ho4/+QZhPurN8pS4d0dM3DrEiEp9cnK1zptS
         mAEF86vYMabAvu5ppafksvj1ks3hekbUa6pqtEuwkkZT+r1qNN8z8odyP23mIKuO4gg+
         wg3YYgb8miCpF8VB0MqXcS08PHsVn1op2k3nrHz7FSwvwcAaM3Ollh17C5oBznZ69d5G
         xt/6N9FiCksQKzFoU/jTYg5tl/3jnyJwuHXV1frV1prM+fKeebMAVDY4BMUBJvPb0Cwv
         gbJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zh7WaU7ewGekRG7I1HMZ6lekH2DZziRDqSPnvPUVHsM=;
        b=D1mOyn1/ymY7ihsHdKaN+FXArb2mvco4VshIjD5jqxITS+7IZ7CICRy826UZXQFkHX
         uIKRFuJZFdexBiykJRAzb9+zPKa5E/5iNAAjyQvP8Az1lvuAMdcZXy5vDbUe3AQ6jcXx
         OTeuE2UGae0yl88dAgkP4kpIebUeSXoO3QVI4BR36vpWDOhO5pLNdJ9M16sl7uhKVHc0
         N4ldW40aIESf+k+gij3gfVuzjrqYMBrHAwsTMmeSOK3eBcvSfeZhiW/7wkPSl9T1xBT8
         Ba3JX7oDF+1fqRBR7oGIBoeKR49VstcZqna1GMJGHVvSEKvw0piMqcbXu8T4DXIGuowL
         nuLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aB2mqO0I;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id s2si14120ybc.0.2020.02.10.04.58.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 04:58:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id l136so9094819oig.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 04:58:14 -0800 (PST)
X-Received: by 2002:aca:2112:: with SMTP id 18mr684589oiz.155.1581339494032;
 Mon, 10 Feb 2020 04:58:14 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
 <26B88005-28E6-4A09-B3A7-DC982DABE679@lca.pw>
In-Reply-To: <26B88005-28E6-4A09-B3A7-DC982DABE679@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 13:58:02 +0100
Message-ID: <CANpmjNMzF-T=CzMqoJh-5zrsro8Ky7Q85tnX_HwWhsLCa0DsHw@mail.gmail.com>
Subject: Re: [PATCH] mm: fix a data race in put_page()
To: Qian Cai <cai@lca.pw>
Cc: John Hubbard <jhubbard@nvidia.com>, Jan Kara <jack@suse.cz>, 
	David Hildenbrand <david@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, ira.weiny@intel.com, 
	Dan Williams <dan.j.williams@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aB2mqO0I;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Mon, 10 Feb 2020 at 13:16, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Feb 10, 2020, at 2:48 AM, Marco Elver <elver@google.com> wrote:
> >
> > Here is an alternative:
> >
> > Let's say KCSAN gives you this:
> >   /* ... Assert that the bits set in mask are not written
> > concurrently; they may still be read concurrently.
> >     The access that immediately follows is assumed to access those
> > bits and safe w.r.t. data races.
> >
> >     For example, this may be used when certain bits of @flags may
> > only be modified when holding the appropriate lock,
> >     but other bits may still be modified locklessly.
> >   ...
> >  */
> >   #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....
> >
> > Then we can write page_zonenum as follows:
> >
> > static inline enum zone_type page_zonenum(const struct page *page)
> > {
> > +       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT)=
;
> >        return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
> > }
> >
> > This will accomplish the following:
> > 1. The current code is not touched, and we do not have to verify that
> > the change is correct without KCSAN.
> > 2. We're not introducing a bunch of special macros to read bits in vari=
ous ways.
> > 3. KCSAN will assume that the access is safe, and no data race report
> > is generated.
> > 4. If somebody modifies ZONES bits concurrently, KCSAN will tell you
> > about the race.
> > 5. We're documenting the code.
> >
> > Anything I missed?
>
> I don=E2=80=99t know. Having to write the same line twice does not feel m=
e any better than data_race() with commenting occasionally.

Point 4 above: While data_race() will ignore cause KCSAN to not report
the data race, now you might be missing a real bug: if somebody
concurrently modifies the bits accessed, you want to know about it!
Either way, it's up to you to add the ASSERT_EXCLUSIVE_BITS, but just
remember that if you decide to silence it with data_race(), you need
to be sure there are no concurrent writers to those bits.

There is no way to automatically infer all over the kernel which bits
we care about, and the most reliable is to be explicit about it. I
don't see a problem with it per se.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMzF-T%3DCzMqoJh-5zrsro8Ky7Q85tnX_HwWhsLCa0DsHw%40mail.gmai=
l.com.
