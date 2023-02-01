Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5V25GPAMGQEERRY4NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5629A686612
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Feb 2023 13:39:20 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id j14-20020aa7928e000000b00593bca77b0dsf4841044pfa.9
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 04:39:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675255158; cv=pass;
        d=google.com; s=arc-20160816;
        b=SD8Xbbi+O5IVGlZU+sARCItfH0L+X4IJK3CyOtl20DLZez/Gd74ec75X4kw9jUfOMC
         S1ejrK+JtjmkeUBqV+ooRa8nWCpq460HKowfAAcENbqOjYazdIXhez+0DZcqBraec+gu
         5MiHBtbqfjaoyttfZGqhYlsnFUZ+cwO4mnm29DHNw9WmVX0fpf0lFfyjFycIamaClTcI
         DtJGwaCXPt9qR6bZRxHoAoumgOKI+DG4btW/QtAgyeKvdbfVQmqBiWGleQS0lt8IcuZa
         +4kv012DcPBmyUHYy8W6ouQ/Z+SUMEtQ8kw4H688yFBdLcVle5HGHQyfQf5ZYIxbL6R9
         QOhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ad/Bm7GsOX+JtmvuZvHyvibQjQLo6aTwwmfEIVc/pqQ=;
        b=N/Sd0EkMl8SzwO8D4N57k5HtL+DAaO1dBm6NfrGzyAqkW24U0Ov9k6D2p9jBYdb6Jp
         AL5pTZ+358dBAUzBK19ZphG3XTSHrUxnSfy7oXklU9RZ5Q2ap1aabOAX/JdEjrN6JUFv
         /Ra4G1cuG4fXN8KI88J543vhdPczIa1MlnsQPAsUayZ74w9ZyqA4ycmnlNoTDBgYruyp
         gY/5pXqpJAqU24+Vl2odE8F5CbGZZNg4vT8xgEI62B2ylu6iz4UqZhOxkka3YbAsOy78
         U+N8bjzF3U+w2aYPl9myO8B9m6gEvQqWQSxFdelEtCu9FdUbuMYDAE0sZEYzcRUjKpzi
         FXUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xm8IDE6x;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ad/Bm7GsOX+JtmvuZvHyvibQjQLo6aTwwmfEIVc/pqQ=;
        b=Tfp5Sv9OBNb+JST5/fG37tyIFYdFA/7Xwxt51oAc7AFvWCzXz1KIUqmG+szkIHJxUE
         wzUWA2LbBHEIw4SyG73y/tkkGdZnzqmfTJRZrD5VZ4DXw2gxDXUzHQ/l0d9J4MtQZ0oS
         PvL9+ejDVRnvUZ19bZ4UnPh9YMoE9vQdOr1YD/FSL4rJYhquxnNjVfxVEVlqBrwOxYLx
         xog0P0dmgZQXuIZPKI7MmuW5vAVXgrxgpvTIILlGWglbNAYcnf0Dv+RGDSu0MyY2pH2a
         UWF7SaW9J8e50xq20wFv3le+DsIbxsYl82OSfyvAMPZIMASho1rMLWVbqzkybFkzCC0I
         4Bvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ad/Bm7GsOX+JtmvuZvHyvibQjQLo6aTwwmfEIVc/pqQ=;
        b=WZJbDgp6WeDpt+SeVkMR/ClXPMLsLY3SST1EgziDmlWQGiNGJbFfbj7LSQ76bU352n
         xI3Gn1OFA7cdMx/XAGbn9OPLXp4PMTazRyDmWoyf19v4EZp/7IZdDa4cNcZ9dHW3zQn7
         1K1Dpwailh0JkLmed1MEkkBMXgqiUkUjfWC6QVoKpWFNYr9YYB5SbAIJFcFsNTb9gf8A
         FJybUI8+7EuBvXsJNDjaeXaS/4Uv5c2ZIxljA18bFiMjEPbBQLEC5g46RwBvAvoRkt2P
         siLDNMis78ROx5XJvNBydgbagXA9QAwXUB87w0rWJb987BwoTPj5ojRexoBG03nSPUQE
         jbyg==
X-Gm-Message-State: AO0yUKXnvakNbWxx4L8IXBne0BuNANGKvOq9bSBlfsgOfZcmuAIbr/vD
	3EIjBL3eCmR4aB9GawWzGNc=
X-Google-Smtp-Source: AK7set/XdP8CyRmI1Z24k/cgDIzsJXZjxsmz1eHqOcAgyo7aUnZVrVuD+U1EOwmP9JrCu3MsRxE7bA==
X-Received: by 2002:a63:2248:0:b0:47c:958e:547b with SMTP id t8-20020a632248000000b0047c958e547bmr363940pgm.39.1675255158527;
        Wed, 01 Feb 2023 04:39:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9f8c:b0:22c:9c93:a12d with SMTP id
 o12-20020a17090a9f8c00b0022c9c93a12dls2268958pjp.1.-pod-canary-gmail; Wed, 01
 Feb 2023 04:39:17 -0800 (PST)
X-Received: by 2002:a17:90b:3b49:b0:22b:b3de:1c64 with SMTP id ot9-20020a17090b3b4900b0022bb3de1c64mr2041969pjb.35.1675255157591;
        Wed, 01 Feb 2023 04:39:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675255157; cv=none;
        d=google.com; s=arc-20160816;
        b=QPdJPwOkgPIfs0KSArprMlcCEynhi53/CyyQ7L68TikOZ7lLukXbpLxzAhecr7Ex96
         /HaRmp3pasKk94SQoFyXWmjnVW5oBAMpBAopzU+uQ0tuvrgb47NsQXg1+HZNiGI3bV81
         b3tfeYhSwd1KBE6HtTQaMQavRmSuG0P9Qlp/p1XDkPrUDf2+rraJjgZM+YAWD63t66Yq
         Z81TtK9gM1Z23n+f5cFXmlFyKV+iusE+0aY2IClZsDn9l3CFuXN3/5Bk3Ou4SrN8+k/i
         QRNdHpUQJQbyljG1HFMX7ug00d7TLAX0Jfos8UMRchwi8V5xcBGPbPTEg+NqkinJWkaP
         I7uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w9SOySbmS0Qu5aNxxomWwuDHN5fw98pINHsIoz0E65M=;
        b=FJV3jwYhRJFT72wDg4u5ZwrOXoWDU/7dqFFxGL6qwUdV93qqrjKf8QrZmLlB+1OiWZ
         X564Dn9J3U8caMUKUWO3NiKVd+8OBN7hJW/33FchxS6JUtx6QVmQrw0uw0IxwxcloBUh
         b+Ukx05uCcQY39T8Dn1Rrkzfz1YzwB5rWIA1HkAcUi4U1PxpE0/Vt4lDCyo1JDqPNszR
         fFpbDSqHpupgHYx96+P7BMi6urfA7XklFJSDaeIL3xpXt/B1A3E9Oa0dST5Mom2UOJrx
         PncfOefK35ECSpKT99Y7hMApETxUYc3gel7kV4CuOoG2t7zOCe9lolUYOxdY0LO+IoZy
         7Ppw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xm8IDE6x;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id m129-20020a632687000000b004de8a48e09dsi1287400pgm.0.2023.02.01.04.39.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Feb 2023 04:39:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-4a263c4ddbaso244789787b3.0
        for <kasan-dev@googlegroups.com>; Wed, 01 Feb 2023 04:39:17 -0800 (PST)
X-Received: by 2002:a81:fe02:0:b0:506:369c:69c1 with SMTP id
 j2-20020a81fe02000000b00506369c69c1mr283708ywn.192.1675255156688; Wed, 01 Feb
 2023 04:39:16 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <fc73ab8b1469d476363a918cbdfe28e1388c043a.1675111415.git.andreyknvl@google.com>
 <CAG_fn=WxZf_kfn8-G8hvoxvUT8-NKNkXuP5Tg2bZp=zzMXOByw@mail.gmail.com> <CA+fCnZdOFOUF6FEPkg2aU46rKYz8L9UAos4sRhcvfXKi26_MUw@mail.gmail.com>
In-Reply-To: <CA+fCnZdOFOUF6FEPkg2aU46rKYz8L9UAos4sRhcvfXKi26_MUw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 1 Feb 2023 13:38:40 +0100
Message-ID: <CANpmjNNgoHdmZEmnOMzBTXZ_Px=fipg-iSk3Hv1fE7MO7+fovg@mail.gmail.com>
Subject: Re: [PATCH 11/18] lib/stackdepot: rename slab variables
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Potapenko <glider@google.com>, andrey.konovalov@linux.dev, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Xm8IDE6x;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as
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

On Tue, 31 Jan 2023 at 20:06, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Tue, Jan 31, 2023 at 12:59 PM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Give better names to slab-related global variables: change "depot_"
> > > prefix to "slab_" to point out that these variables are related to
> > > stack depot slabs.
> >
> > I started asking myself if the word "slab" is applicable here at all.
> > The concept of preallocating big chunks of memory to amortize the
> > costs belongs to the original slab allocator, but "slab" has a special
> > meaning in Linux, and we might be confusing people by using it in a
> > different sense.
> > What do you think?
>
> Yes, I agree that using this word is a bit confusing.
>
> Not sure what be a good alternative though. "Region", "block",
> "collection", and "chunk" come to mind, but they don't reflect the
> purpose/usage of these allocations as good as "slab". Although it's
> possible that my perception as affected by overly frequently looking
> at the slab allocator internals :)
>
> Do you have a suggestion of a better word?

I'd vote for "pool" and "chunk(s)" (within that pool).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNgoHdmZEmnOMzBTXZ_Px%3Dfipg-iSk3Hv1fE7MO7%2Bfovg%40mail.gmail.com.
