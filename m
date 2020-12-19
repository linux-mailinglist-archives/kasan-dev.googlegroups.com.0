Return-Path: <kasan-dev+bncBDT2NE7U5UFRB6XJ677AKGQEQDGZLGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id CC31D2DEECF
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Dec 2020 13:41:31 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id s14sf3547344pjk.4
        for <lists+kasan-dev@lfdr.de>; Sat, 19 Dec 2020 04:41:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608381690; cv=pass;
        d=google.com; s=arc-20160816;
        b=gvfgz20XcAfFsqL4lM6T9vgdy8Cb7+YGHIzqY/oQGomKCSEwJNuS8wPjiGc6x+fKFQ
         or5qJ+ji24uwB24onhJcL3uGMyWZViguoucthguuBXoqkko4mR+9bX9kMvm34gjyl/T3
         hBRoVigZB3NJSTkZX0kl7TrIR1C2X9LCaa0ES4oO9vv+H5BOCfTmz1WBiPEV917Ms9cY
         TOqUNAlAjkVuD+h62RQttx0cX9DXxXlCqOgT19+DD3nsL8qF3iFjLWaZHUBl0HzDThwC
         IXfpuX7V3i/tfscY3adwCk7QPiQnG/n0pjNxjz8wmlaZ0G4fly8pBlsCZhs3axvltUXp
         G2fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-filter:sender
         :dkim-signature;
        bh=s07pLZk71cZpCV9OssqRsSLy9fUds17AKrn9azCYN4s=;
        b=nii7p++VWK46mrT1jzZOz1OTzw/nOkxzix7BEA//GCKugAYqycv9m4Opjwtjq7tkNn
         tEdyMmaXTCb2F7BQ63n956jktsdXJ2SOvlf/iCTNb/SZJWmR8DFGh88fn6IV0IXxZTws
         dnbcR85yIDFzCD6R2Hme8eCVhIV3+U0z3rAj0jgiaZZ7HzEOxGaBoerUi/G7mK1sliSb
         hIJssKLgkzd4fIrURnR8M2W31GiK7oYxQSi/JgOc43jN5yfpWxgAulXl+4/xP1Ds43+R
         DH5SoosO5afoqcUSRtmtPElvQExriYgGojj74eJSn64C5Sca864QHVv3sgc7LIFzlN88
         BmBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nifty.com header.s=dec2015msa header.b=DHBZz6JJ;
       spf=softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.90 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s07pLZk71cZpCV9OssqRsSLy9fUds17AKrn9azCYN4s=;
        b=sAK98Vk0eoWqA4BqEPzlChx/5LWpbZxecRoGOrlJWlB11VkVIi9K5riUyfviFkF8/C
         FafQSOhOCDNspWqzypU4hfEhTCm7y7GxZeQP4fcPvtwNxy+6YR509bZDS8r/uaetDEmS
         PG5PvWUGH3lkY6HCxB3jqswykxllk0wcDOKIleKHeOKQBm0s0iyPAyAAiOclBTwlNuCv
         2r+18EL8TNmIEl2QinS6eSVJXP4JlchbmbjlW/oVY515hjYt4Jb7nFK18j3815PQqpCt
         Kz2PvDTzlWnrPPE3tGusGOmPPjbfy7sBoZIt3DqyiThuEO///E4PS8svdSvqoTuB47na
         E1Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:mime-version:references
         :in-reply-to:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s07pLZk71cZpCV9OssqRsSLy9fUds17AKrn9azCYN4s=;
        b=HhWrWNhubgV8imbW9b2f4xPaYXH90Y7taf6cKW7S9zzfkSe6CaZAEqSJDS6CRYX1uN
         rttenrwSImeXad87Ho7070tH0J7rdBHV4JowC2FP62nDzYc35l9zHejLbQuqU26wMgFJ
         72WJ8Tm9ge0G644uLLwRFsvuSw1057avqqKSXbuuTypX4Ev8itbRf50nytXm6srvOry2
         vMcV671JKRLmF8FfyFKZM2VdDL8SeqCF9ImQ0bUFnZ2ZGAmPmnqccUuFK1ttTsiRgeCF
         oy94mgAXjV1y/QOPoSkIpH0GtS4gJPRSXBeEMtB3votox/BrZaBrrASLRS/y6SDQqxBA
         U8Ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XocagFOwWOIbIUdFQh+dGj0gRYunHvkyD8cImCr6eCEirofie
	+QPLxap7HxFtWpmeMB3bS2Q=
X-Google-Smtp-Source: ABdhPJws3ziIF3zCSClNcpRR7ZBmDtTYj2RJSXT/q114CBNY0eRo8ctVTRZs910EfuqLr7EM+Fh/Kw==
X-Received: by 2002:aa7:9a86:0:b029:1a6:d998:922a with SMTP id w6-20020aa79a860000b02901a6d998922amr7996659pfi.80.1608381690541;
        Sat, 19 Dec 2020 04:41:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab83:: with SMTP id f3ls15955472plr.9.gmail; Sat, 19
 Dec 2020 04:41:29 -0800 (PST)
X-Received: by 2002:a17:902:ee0b:b029:dc:1aa4:1123 with SMTP id z11-20020a170902ee0bb02900dc1aa41123mr8634173plb.18.1608381689809;
        Sat, 19 Dec 2020 04:41:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608381689; cv=none;
        d=google.com; s=arc-20160816;
        b=HfkYCjOee9TXWFOtBwL2STS7HqfbGx4u15IHgPwv6Od9Vkl5ZRznpXDW8YNuLwktyP
         dGKsv1NgEDo5n/kviTduwTR2MnpPNg9QcakLog2JrkchGoEW7iIFKId+NIjw5XNR2UxZ
         /nJozHbFQymJvYdVc/zOaf7WS/H1sNL+ZexDiJBb/0HwAHpaWgefdEuhDFX8NAXpfI9d
         l8/IQovlMc/F485/NtJkDOZeSqM3vIsFMuiGfm/Ege9h6OcvUKGWSBwRLG1gxYrOHvA7
         0q+n9Wk31WmMSWMkYmFFxdL7GT0GV0hq1mWG53sz9UXN4iIrzRviIZAKuHJADnH9lrJe
         QnUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature:dkim-filter;
        bh=/QShfHRRh7S0yQZEAxp8XGYY7a3VQZZJR3cuWY/zEU8=;
        b=NXnte20m/B1UGzQW0Q9BgihwJbWrZMKLmymUwmix4G5jG/GMtj4OMZ7ySKSw93MW//
         CKaunikW4i2PJTOzZb2XklGOPYjqSBbFyHnwOHFov8b3JC9AU/ZxdVGBRY0QevQ6RHnQ
         byydnezFRTHcz7qXvcStxBO2Qz6udG2FL0nQHvueWnakwlMT3+yENhMbrZ+ltMVeNggh
         c7O49S0//GoyD1p/O3caX+KmhlOw+kIVzxBumAxKrupzgMJ/mNKSIRwjq6b8ZMS8r7TA
         Z4bCrEvAwQP2pBjXrvaXXUXb39AWH+zehPTGmSIFN2mob4ENPwIxzw50UkSRIjhLEwFd
         Jg3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@nifty.com header.s=dec2015msa header.b=DHBZz6JJ;
       spf=softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.90 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from conssluserg-05.nifty.com (conssluserg-05.nifty.com. [210.131.2.90])
        by gmr-mx.google.com with ESMTPS id 13si905699pgf.0.2020.12.19.04.41.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 19 Dec 2020 04:41:29 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.90 as permitted sender) client-ip=210.131.2.90;
Received: from mail-pj1-f46.google.com (mail-pj1-f46.google.com [209.85.216.46]) (authenticated)
	by conssluserg-05.nifty.com with ESMTP id 0BJCf6U3031880
	for <kasan-dev@googlegroups.com>; Sat, 19 Dec 2020 21:41:07 +0900
DKIM-Filter: OpenDKIM Filter v2.10.3 conssluserg-05.nifty.com 0BJCf6U3031880
X-Nifty-SrcIP: [209.85.216.46]
Received: by mail-pj1-f46.google.com with SMTP id f14so2874355pju.4
        for <kasan-dev@googlegroups.com>; Sat, 19 Dec 2020 04:41:07 -0800 (PST)
X-Received: by 2002:a17:90a:d18c:: with SMTP id fu12mr8623337pjb.153.1608381666291;
 Sat, 19 Dec 2020 04:41:06 -0800 (PST)
MIME-Version: 1.0
References: <20201201152017.3576951-1-elver@google.com> <CAKwvOdkcv=FES2CXfoY+AFcvg_rbPd2Nk8sEwXNBJqXL4wQGBg@mail.gmail.com>
 <CANpmjNOUHdANKQ6EZEzgbVg0+jqWgBEAuoLQxpzQJkstv6fxBg@mail.gmail.com>
 <CANpmjNOdJZUm1apuEHZz_KYJTEoRU6FVxMwZUrMar021hTd5Cg@mail.gmail.com>
 <CANiq72kwZtBn-YtWhZmewVNXNbjEXwqeWSpU1iLx45TNoLLOUg@mail.gmail.com>
 <CANpmjNN3akp+Npf6tqJR44kn=85WpkRh89Z4BQtBh0nGJEiGEQ@mail.gmail.com> <20201210212416.15d48d2a924f2e73e6bd172b@linux-foundation.org>
In-Reply-To: <20201210212416.15d48d2a924f2e73e6bd172b@linux-foundation.org>
From: Masahiro Yamada <masahiroy@kernel.org>
Date: Sat, 19 Dec 2020 21:40:28 +0900
X-Gmail-Original-Message-ID: <CAK7LNAT3A-YE2W=DkUMVc8Br4qkEjzQx=qhHMOtWDeriY2RtZg@mail.gmail.com>
Message-ID: <CAK7LNAT3A-YE2W=DkUMVc8Br4qkEjzQx=qhHMOtWDeriY2RtZg@mail.gmail.com>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>,
        Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
        Nick Desaulniers <ndesaulniers@google.com>,
        LKML <linux-kernel@vger.kernel.org>,
        kasan-dev <kasan-dev@googlegroups.com>, Joe Perches <joe@perches.com>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Richard Henderson <richard.henderson@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nifty.com header.s=dec2015msa header.b=DHBZz6JJ;       spf=softfail
 (google.com: domain of transitioning masahiroy@kernel.org does not designate
 210.131.2.90 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Dec 11, 2020 at 2:24 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Thu, 10 Dec 2020 17:25:30 +0100 Marco Elver <elver@google.com> wrote:
>
> > On Thu, 10 Dec 2020 at 14:29, Miguel Ojeda
> > <miguel.ojeda.sandonis@gmail.com> wrote:
> > > On Thu, Dec 10, 2020 at 11:35 AM Marco Elver <elver@google.com> wrote:
> > > >
> > > > It looks like there's no clear MAINTAINER for this. :-/
> > > > It'd still be good to fix this for 5.11.
> > >
> > > Richard seems to be the author, not sure if he picks patches (CC'd).
> > >
> > > I guess Masahiro or akpm (Cc'd) would be two options; otherwise, I
> > > could pick it up through compiler attributes (stretching the
> > > definition...).
> >
> > Thanks for the info. I did find that there's an alternative patch to
> > fix _Static_assert() with genksyms that was sent 3 days after mine
> > (it's simpler, but might miss cases). I've responded there (
> > https://lkml.kernel.org/r/X9JI5KpWoo23wkRg@elver.google.com ).
> >
> > Now we have some choice. I'd argue for this patch, because it's not
> > doing preprocessor workarounds, but in the end I won't make that call.
> > :-)
>
> I have
> https://lkml.kernel.org/r/20201203230955.1482058-1-arnd@kernel.org
> queued for later this week.
>


Sorry for the delay, Marco.

And, thanks for the proper fix.
Now applied to linux-kbuild.



I will revert
14dc3983b5dff513a90bd5a8cc90acaf7867c3d0
later.





--
Best Regards
Masahiro Yamada

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK7LNAT3A-YE2W%3DDkUMVc8Br4qkEjzQx%3DqhHMOtWDeriY2RtZg%40mail.gmail.com.
