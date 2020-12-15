Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5OI4P7AKGQEYZ73LAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E4512DB162
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 17:29:43 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id 193sf13624590pfz.9
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 08:29:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608049782; cv=pass;
        d=google.com; s=arc-20160816;
        b=WPZegZsLw2SmQz07avnIVnCbhYWbAfAaTrGzLTPi9X8vG5NCvzYl2ZtZwzjhvPDEL6
         CUcYRrAeQZVqPWTccHn6NflGVV1h/cAjIbyYV8Fw/EHiD/bLoDoy4XDC6uwtd2t+lU5D
         T5LhyOdWd4Gak5RAvWP/WsHY1bycGGTQuLeX+2IyyTxBp8pz1TidJV9LzyWXKDldeWyA
         C2UjGk08VKr45ctyj3Shq1FCPTTbw9Rjhr4ipasTAdepU3ywhbs/Mp5ZOXY26Vwj96Ly
         8AjLpiXj86UsV4H2K7erqVsKz7+S3urIqQbEQTMhjhtjPhr6LKzp1OR0oojhNLmTzqRH
         dJ7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EW7cIfkfPPivVBfaDCSbUZFOWlPrRQgBbZUSToeniIY=;
        b=F9l4k/3ZBWQk1XvhSr3jmwhvvcopw1oG9Oc8avyr5j5BwQk3chYJTipJsZKxAbCzyp
         GLHByzbaUoCMBs/7QsoYlduprF9YAvbMHmkP1k/6I/V3y2/tPDE5fzcs5PRkV0fNvfj8
         BVh8qbxH9jKWpBwSynXK+oQCZmUjAQeK3uiW5yLzyGknZs8vV6eQ2CHaRPhPRxaS/22q
         +J+P1yCegX9FuXNx5/8Dsa4g6U38lBQ6VjF8Hx0x1VZFHU99Z0LUwosE6b4aMrVf7cVn
         TD/NbQLswZ0aLMSJ4mwlBuO+7BxAw4JwKZExv+oXh0Or3clESn3G0aibMhdYBjEl/xPn
         WSpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ny/i0Kbb";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=EW7cIfkfPPivVBfaDCSbUZFOWlPrRQgBbZUSToeniIY=;
        b=fkf/SIpqu7P0LkydA8DgPiYoUhC9RwuWsrhCWnyewKb2cvpGANbh8NJA0xNHRMc/V5
         9QpF/AIFo+rbsC1ybwlCZa+8SlMXCf9/5HwU73phuk9FayHKHypIndeKh+ZentauuMPU
         BHXKz5WhSDF7KVXWU2bM6GfTDyywsLGlz/llcozHkWnmV9aVHAL390DoO7l85PrSwbba
         U2iyFxwW6g2064NstUq4rGPsG01tIr77zVpWlsX9OzH7ZY+mzTbvBXTukeg99Jy1PylV
         YJb1HRwfPfX/i7MBz6aFabG6o7BwuBxveKKvzcc1hyrKp4QsPd+zgfL87L22qdxPE0Mn
         agkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EW7cIfkfPPivVBfaDCSbUZFOWlPrRQgBbZUSToeniIY=;
        b=gMZk7pNcKBwfzwWufzaxYACUvr/fPdT86WYp8EHQrK4aEpai5gHN9y2ItFa3dYhAfI
         S9I64KxW9zHM1ImhuzCevbRBbL53Hly79BQSLkk/gXKZQyNqNv6DN+/RgdgofGg1jlcQ
         K+6FX73MUPhkakU5uHYNrUgKj7zEL89O0Y7x7ZvIi6oXfE62TH0FcTMKHKT1fjdtql8P
         D5raOYP3L0H62w5jsHOG6prz18uwq0kMf2UDBe8pkzI+Waj6CYqOAXeWYB686rTQ21e3
         yuQEBvjap/QpqxJAxfhzgiWxxKd94pxXJ05Pb6tHBkY250gGqA6ORqNFkmm5p/DFQdvS
         3dGA==
X-Gm-Message-State: AOAM533pCcTQ0nFJE5OIdShqzQINJpqphIYcwR+AjZYbQEMktrrV9mdu
	lua4dw7mzPaNuLjPtuX75JI=
X-Google-Smtp-Source: ABdhPJzs4DlrG5MysKJwKwKGAnhsej9BnAmVL6rvkQck4xNcq6kKCZkrCEHEzNsrrQYKsx5AK7RHNw==
X-Received: by 2002:a17:90b:fd5:: with SMTP id gd21mr21401026pjb.139.1608049782115;
        Tue, 15 Dec 2020 08:29:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ba8b:: with SMTP id k11ls4876042pls.8.gmail; Tue, 15
 Dec 2020 08:29:40 -0800 (PST)
X-Received: by 2002:a17:90a:fa81:: with SMTP id cu1mr30991272pjb.39.1608049780054;
        Tue, 15 Dec 2020 08:29:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608049780; cv=none;
        d=google.com; s=arc-20160816;
        b=yaMwRKWnhAmLCnI6N1DW30eBWva4Qae0EaSQt2JAi8+bG7TXdjLBx1znAW+6CUuXy1
         gg63+jlhevn45b39nTkEBfloZ168ZphYLp/e2nDvolDGwoVEZalkZXwavTvXL6c7I5Tf
         25n0qoMnfQUrm7RocRqtP59mwEgRWqihPTDhQ+IM/FHSA5oR3bRnZmmsSOs0Bzbb+5pE
         F0c1ntzI6+7jNW9cI7ZytEJj2WeDZHhaS2MITtB5TGVdy3EI/Kcjl54h/qk5TM4skKOt
         R0jTAT8BC5xAFoZPgmoehPzuj3r4nWTKv4Pd4QL8nIbD2inbLwlUAIjO3+XSBTbb3RZ1
         eJNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sHaFXLsoqoiy5h0yxOi4VaXqWA9O2PeKl58dUxRrXfY=;
        b=JBGQ91hXxfV9kN00g/y9Zbk+Z1fll+y/5zHpWDahrsE0VZNMXnoOn4LZl5mt4zGw1C
         oR3QLQxB/4swXUepexVg31zR3bnfClUcknyz7UwE7wFRiijmS7k+L4ytDdgbr489MBZ6
         Z8n5YfpIk0g/pIst8joqU6CPuDVptVe5qanG54Lwvi3ax1MGw5FTKayjzV+6JmCE/cRD
         gDeEcrI+9LuHjq9EiMXFZOKi+ge3bl/Tsgx6irO8qCU0G3GfmXLItz4nq/gBQWb4eYoK
         FUjHtS7953KULpx/wydngZ89HGt0g6ABTcORpRweiqtchkPY0W1c1Qm3lmilcl+j4eT9
         Dbzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ny/i0Kbb";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id b190si161422pgc.1.2020.12.15.08.29.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 08:29:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id w3so19915190otp.13
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 08:29:40 -0800 (PST)
X-Received: by 2002:a05:6830:19ca:: with SMTP id p10mr16999931otp.233.1608049779493;
 Tue, 15 Dec 2020 08:29:39 -0800 (PST)
MIME-Version: 1.0
References: <20201215151401.GA3865940@cork> <20201215161749.GC3865940@cork>
In-Reply-To: <20201215161749.GC3865940@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Dec 2020 17:29:28 +0100
Message-ID: <CANpmjNOKR+SSeQ3=DBzTgwLwRDZ8ryapcVpKGGYOWhYvUN=MzQ@mail.gmail.com>
Subject: Re: stack_trace_save skip
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Ny/i0Kbb";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as
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

On Tue, 15 Dec 2020 at 17:17, J=C3=B6rn Engel <joern@purestorage.com> wrote=
:
> On Tue, Dec 15, 2020 at 07:14:01AM -0800, J=C3=B6rn Engel wrote:
> > We're getting kfence reports, which is good.  But the reports include a
> > fair amount of noise, for example:
> >
> >       BUG: KFENCE: out-of-bounds in kfence_report_error+0x6f/0x4a0
>
> One more semi-related question.  Can we distinguish between
> out-of-bounds reads and out-of-bounds writes?

Well, we do have X86_PF_WRITE, and could probably check the error_code
and then pass to kfence. We probably have to account for cases where
we don't have this info, but in general it should be doable... let me
synthesize a patch.

> I have a log-scanner that generates a one-line summary for all
> interesting events.  Back in the day that used to be "Call Trace", but
> being more specific allows me to skip over lots of stuff without opening
> up the actual logfiles.  And small details like read vs. write can help
> in that regard.
>
> J=C3=B6rn
>
> --
> There are 10^11 stars in the galaxy.  That used to be a huge number.
> But it's only a hundred billion.  It's less than the national deficit!
> We used to call them astronomical numbers.  Now we should call them
> economical numbers.
> -- Richard Feynman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOKR%2BSSeQ3%3DDBzTgwLwRDZ8ryapcVpKGGYOWhYvUN%3DMzQ%40mail.=
gmail.com.
