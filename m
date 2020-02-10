Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBJUTQXZAKGQEVXQFN6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F23C157456
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 13:16:40 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id p7sf4862891ilq.16
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 04:16:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581336999; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ni3i24AkWXnOiZxckRuVllK6L7CaPijcF8vsLYEsxYMru7Njdh3Aq4zkACUD2NHaGT
         +DcgIGvXXBWdI6pihmj9giDFMOHpkNpiP7lrDbhJ6z/hjSzHz3ideXGTS+4t3jY1P/RJ
         BWNUvVY6phm7g71hyAiSe5AOkXRlAZ4KdAYhmtS/kuV9YlkzvXFjcuL5sSiQu+gokam/
         wjWQ5xLZv+Rqi6gVDtqKcZAhO9m8Jaeu6LSveRYY4xeyBrukHsVQOvVit4vPohs22AMb
         3wv8uIY2rs5zWsq+fEGl+whAU8G1ubP4OYsA/UvbacO8hC8mT8mdTsKSG1ABPY3THecV
         VJaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=b0iM1a5zpky45aWYjxY49LUsn/HTWZ/TUKUA1/QzaeA=;
        b=ISve1iIFmiMbtxW76O56VDcOZ96GQtvg2wJRK27rj1VhE0zrxehtkZzSRFuXQHAK5d
         bYUYhfQkBONemYuimNna0jqdKuq6/oyCVwaRyciYyeKw/A1LMgLacidy9zoh7syv88FY
         WLixL0vKPl2x3BJZuLrLca4IkXkbdNKZp40DMqYXfHXY3qC/Yc9Vc0iA0vv6JgCd4k6r
         QHGumqW4LfpRatONX4i/JYB13NexYfRfIWzCdCW3YSrDo0ANqhHYkZG4RIALBFjSaeYF
         DlANloFr7rEWoBchc22OiU0LcNp6TS/mWmsCeajzGNkxcz8UidP1wegFjZIX2f2ECMx+
         QwEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=a+Nlc5bM;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b0iM1a5zpky45aWYjxY49LUsn/HTWZ/TUKUA1/QzaeA=;
        b=Fco4gidIJ2DznruQzQWgOKTs8XTVNvxEmejn7xcpQr/rTVtKzQ1MdtspehPJK1ZJIB
         zJTNUFRm+oL3pes8SLWgMap10qm0rNnxtNwHKNByoCAX+JBvfuOz0tnpopm0SSSmt5ay
         ++ZI+jkIBd/QAxVR61PI5Pc6H81f9oVBAF7zQWso8MiGDVcxedcCJ2i+wpNKVh4oYJtK
         xKMSBQ4avES4NH8rYWMeaGGJZCKpflPaRfJK28z6kl5ScpJuBE/0PzmEX1tAS3sERN/E
         jCN+FRSMNbgdhnyj3jnIjckbYS8Ta44wz3/bSR3TcAGquCYIyVCrlrMg6vXUISR/Ijcu
         tY/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b0iM1a5zpky45aWYjxY49LUsn/HTWZ/TUKUA1/QzaeA=;
        b=Y1xs+stsAMeQdwMdWFtU+Lz0O9viGS8eleXV1vMQ7fW4aqIzhf6AMg/G94neQt1gpZ
         mFsSL5JH8CGizAXiAj4wGZiYDxQiEhaTI/QQvQstdjxpMgamuns+k+UzfF0Qd0XqDFur
         7+6gBgJmlkD5eoaOWAhLFHWRM9TyNzQHqny5MDMQs+aod2JLN/gqbNLaBGT6PV2re6Wz
         INiXSVmxfPsX2L++WUD05lc+76DqM8X50FsJbV5kd7SsUTvbj+qhoGtzDzvobgTxdr3y
         gdn1DtgAvsv53Pf23q8mqkld3isSTmc68oTpA1GEEm6AxEfp4IM+djsvCg8Ptw1aguI6
         8PQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUiAmWqXoKtyTVIfbz3HPw5b/L28ucoXA1GndtWBme0gbD7FyVV
	rdAeEq9eukMl37/nLNfLryM=
X-Google-Smtp-Source: APXvYqw/TYvNgCnobf7vkxkgDlwA1UTZelM5Zg4Fmn68gg9MuXpPlkumjJB3g3UNEhsHl/269DrUkg==
X-Received: by 2002:a6b:d019:: with SMTP id x25mr9020341ioa.275.1581336999064;
        Mon, 10 Feb 2020 04:16:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:39c5:: with SMTP id h66ls1553637ilf.11.gmail; Mon, 10
 Feb 2020 04:16:38 -0800 (PST)
X-Received: by 2002:a92:d151:: with SMTP id t17mr1083968ilg.175.1581336998724;
        Mon, 10 Feb 2020 04:16:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581336998; cv=none;
        d=google.com; s=arc-20160816;
        b=TPF1Kb4UzUpEb305bVKgCbOnktlGYFIEajFtd5JGA5c2qNUOy70kLUtuGqeqUBqMju
         qhCV1VVoZYDg7o3hAynifaUDX3sLuQizhCwWdxziq2/MAIOaICZ34oRRT+yjOcDdp8Wj
         hpctsZ8HfqOC69l5cwXkeNVXdlExVE0xAlGwZZ8g7EzGL+WM2FO7pZLuD4fTzZ0BqLvh
         OKeyNc7y2NkRi97Pgn0Kox3ZD7GWnEkNFLxeXMNpopOjH06LvDRPNJUA18MieIzw43xi
         z4+MC+uR0F0kKxU7fH3qcOzdeL4TiQxETpC70qQN/7Is17jFawlwuPpkltLKPYjV5tEJ
         UXKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=jOS4lF/HfGt+hqkWTYE7/ikX0I8M0rt4XoEg2BiMX2I=;
        b=jyKgoPi674Z9/P4/pCFquqbHEcDlZufB9UMVaPpvnNZc3CwNras69687PvVQSD2hMZ
         Y6NP+tG4JQPLmtjDVgJKKUyJHMRNcvfTjCKJNcwptjMHuv9CPtnQWnp0NtxIs98LbZ/U
         iAcxRkeB4f4nHUyr54Jc5dxxunK/9oqF0+dOG2gw5pHNWHkgNaaRvR998BGJJegNqtys
         BoicGQIX3PMtxRVsA8hMxi8OoKEbldFO7Q+Dkealttp7LNDbkKVPiMuZPKZFEYXlME71
         43nQpRs7P9BVCEnscDQZ6et9dyJG1epxkq86gDFcyci7Y6IFv8RT/tbQ5EeuGNTOvX0G
         WEGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=a+Nlc5bM;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id k9si4387ili.4.2020.02.10.04.16.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 04:16:38 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id n17so4937919qtv.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 04:16:38 -0800 (PST)
X-Received: by 2002:ac8:198c:: with SMTP id u12mr9826102qtj.225.1581336997787;
        Mon, 10 Feb 2020 04:16:37 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id i13sm40735qki.70.2020.02.10.04.16.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 04:16:37 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH] mm: fix a data race in put_page()
Date: Mon, 10 Feb 2020 07:16:36 -0500
Message-Id: <26B88005-28E6-4A09-B3A7-DC982DABE679@lca.pw>
References: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
Cc: John Hubbard <jhubbard@nvidia.com>, Jan Kara <jack@suse.cz>,
 David Hildenbrand <david@redhat.com>,
 Andrew Morton <akpm@linux-foundation.org>, ira.weiny@intel.com,
 Dan Williams <dan.j.williams@intel.com>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNNaHAnKCMLb+Njs3AhEoJT9O6-Yh63fcNcVTjBbNQiEPg@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=a+Nlc5bM;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Feb 10, 2020, at 2:48 AM, Marco Elver <elver@google.com> wrote:
>=20
> Here is an alternative:
>=20
> Let's say KCSAN gives you this:
>   /* ... Assert that the bits set in mask are not written
> concurrently; they may still be read concurrently.
>     The access that immediately follows is assumed to access those
> bits and safe w.r.t. data races.
>=20
>     For example, this may be used when certain bits of @flags may
> only be modified when holding the appropriate lock,
>     but other bits may still be modified locklessly.
>   ...
>  */
>   #define ASSERT_EXCLUSIVE_BITS(flags, mask)   ....
>=20
> Then we can write page_zonenum as follows:
>=20
> static inline enum zone_type page_zonenum(const struct page *page)
> {
> +       ASSERT_EXCLUSIVE_BITS(page->flags, ZONES_MASK << ZONES_PGSHIFT);
>        return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
> }
>=20
> This will accomplish the following:
> 1. The current code is not touched, and we do not have to verify that
> the change is correct without KCSAN.
> 2. We're not introducing a bunch of special macros to read bits in variou=
s ways.
> 3. KCSAN will assume that the access is safe, and no data race report
> is generated.
> 4. If somebody modifies ZONES bits concurrently, KCSAN will tell you
> about the race.
> 5. We're documenting the code.
>=20
> Anything I missed?

I don=E2=80=99t know. Having to write the same line twice does not feel me =
any better than data_race() with commenting occasionally.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/26B88005-28E6-4A09-B3A7-DC982DABE679%40lca.pw.
