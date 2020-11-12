Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJFFW36QKGQEUHIXLZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 663252B0E84
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 20:53:09 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id w189sf5047947qkd.6
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 11:53:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605210788; cv=pass;
        d=google.com; s=arc-20160816;
        b=XNEJqAtvxo2czowiQYL2RWub4DKXldtbqJvFctxiNApRgN5ncH1sSUupMcMkogjkfO
         3MTQuZSnwUq68FNTAnTdzd4AEkcsu3UOo2I092WBAO4ZUrBeoAmkSVfXWKUdyrT6iM0d
         0Eb7h1vOWau2N6zZNSPCRkVZZ8GmdChEJ6ImnkXhJLxUBjEN/uJU3IxwLP4XdHhPcYto
         ZN7eBv7+q5Tely807xcpWVynVRD50AccXSlxR2STqyZL6C+XhAGbWU4ZQo7+JTEfZCtD
         /OaJlt2t0Z50mpQMBdSMv88H8TM8blo4ouVpP6Of/v28/4wJriJW68e8hEpis5+8Sysh
         70JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gespkIkHuuRYhYuNdW6d6EzIDgkiEDfLy+an12dmTsM=;
        b=l3TGUvK5+UDxkQCv8RERMLNGTfHWmi2X30xbPKsLiGKelJ9/OaQNGTqZ+yJgBDUTlt
         C6nEJvaN4KWVkREjfOFfezmmUgu2E28LzTKq/e7xfwQz7qihmgNFlr886Lo/tcOsw9M3
         TIqIOHPXB9ZaqKZ54gkZ1IbIT1x+3ef4tNsuUc9aGcnb8PpFYfb/xo0C66SJoKc+1qmM
         sOec8xRvcOzfrB8x+nNAIbpS45GFlDlNUF/mC38Hn0cRNnbRn3fNeFI/fEhkzeeHJfD5
         mu/OUL4ndihzhXYZyq2FQjndJYCV+YlYTkZLikItNhEO7urcoP/myr0SSXtm25lqNvHA
         rsAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VD7H2eMa;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gespkIkHuuRYhYuNdW6d6EzIDgkiEDfLy+an12dmTsM=;
        b=NRaYy321aGdiFnWiEIVV9Cvrp7xRlv51y5ml88G1Z0UQYgbvfRmXJZEVSJ1msn6XKO
         M8BQkyUeT5Rf/bcKxVPutcAAWgKNbC9don8iH9qIMZ+gF4Cnyi8tE8V1NH2F+GDfIVQr
         w+IOIHA2D3tuworbJPDzW6awRh3UlY+F/ibnD/uDxzFWlUjy3UbB6Py49/9oiwdvScn+
         F2LW2QMDmHzppJ02IIgqpdCSq1kRWtsl9+H43I96Z9DQZ8LiyAjtkvH8sJy/sVqO0B5V
         yO9vDwF2seoBTvwGwRutU74v+lPzE6o5gnpz7DPiByGSq/VfhruRIC4GDdC3yNQKNn0E
         4/Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gespkIkHuuRYhYuNdW6d6EzIDgkiEDfLy+an12dmTsM=;
        b=Esg7b/lFoSP3hmRF845i9VXZvQLlh4ogpF+1gT28S5RuV4fA9yTNKyfjyk6WBtmNWQ
         bDzp+ccAsj1BnKDKe0M9AAr+ItFNUBYZu3WRyYITcS4QYnE8soELpqlpbsQdGCOkpMvO
         0zNqnfS3w3Nt1qmiRPY+Aw7NMwwd6+EoDJE513jGjp276enYvvDcXSYzegCB1t+ZWgV6
         ZdW/sIP5vDvhP6udreVa68EBjbPlt+OX+y/U6Zo/BRjIKNaD0rYwvLx4bNXssgvR2JyT
         CPy+ZNYZWBFukx1kAURKCwrJ/MEpUK4V34YPktQkzs1X1HTzSaB2yzmVXr6DaJKAFpnq
         E43Q==
X-Gm-Message-State: AOAM5325/kyk7I4GvbGdd0qfK3OYD3c9y50yZfaTYyiZqsSKgTzswVNj
	4kVpGxlynUQEE7Okv6qNKjs=
X-Google-Smtp-Source: ABdhPJx6+OWBP9Y5ulrbSlV8T1pSorYcrcYItRMTGqWtuy+vkNYAJuMRXZPkrVpr0whauxZOSmSIvw==
X-Received: by 2002:ac8:24c2:: with SMTP id t2mr840292qtt.295.1605210788369;
        Thu, 12 Nov 2020 11:53:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:80af:: with SMTP id 44ls927811qvb.2.gmail; Thu, 12 Nov
 2020 11:53:07 -0800 (PST)
X-Received: by 2002:a0c:ab5e:: with SMTP id i30mr1474280qvb.34.1605210787895;
        Thu, 12 Nov 2020 11:53:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605210787; cv=none;
        d=google.com; s=arc-20160816;
        b=0wSAssaUBo/BvsuzJQvNF5hbbUW4vBlJjypZB694wJh1DHD/sbHfgVRJeHUofIS/f4
         RHiwdfGd+YBGrbIQlXKHuoieHnUGOBMLoEeJJ+OI8dOi38g8pcwCBvDomyBGJIc0QAiG
         xvxe5LhtuuPE7iYzXrvX9gQ3BQW6zYK+xjz+D0WOK9t3tpxgTbdGGJJ1LUSmTEVnlDLI
         sFInUGUW0i6+5rB06pSebro27cMHgOM8HrCATbHTV1YMClhQbqZQoNJP6CjOlo1SaP5B
         HxsxT8aDFuX6lqH7HPFaFL5D3izDEjbCzN7mME3tD6Zvjxy+bJCmqjPSQ6in1QGSscex
         ARVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=R1iBhmRyOD1cXj7AK8WZ6mc3iAS43Zf94bygMHusk1g=;
        b=hHoBULyEKVxnHl5MbZh51xJt2X6ZpeFURJHvwTTMBH9hZ+FD/0NYARvw45Bg+g2QNu
         MrE38HRWXjMsdXe9RHnxOSsSp33jJxbkNY8h5Y8U1CfV1qE6UTCnlvZcgCs25iVDDNZF
         63qNwCw6Eh7c7rtuFE7KSqqeoZ727eyuhky59M4Jj7kpMKxKX5Wi5DhzVEgJF6iiXnYD
         Nu1ajx8te91vG5SciuDwOwxCanzDaMX/e32natwZDs+pPQrwnHz2zT8vdh/F/99zVJzz
         U206VkcPJ4t51RXX5d7x2iLAeN4WmAWhnZUXrSPXIa6UBpb/6akB3uLusbitLEPho3x4
         eHxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VD7H2eMa;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id p51si429544qtc.4.2020.11.12.11.53.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 11:53:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id w4so5066875pgg.13
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 11:53:07 -0800 (PST)
X-Received: by 2002:a17:90b:3111:: with SMTP id gc17mr842079pjb.41.1605210786958;
 Thu, 12 Nov 2020 11:53:06 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
 <20201112113541.GK29613@gaia> <CANpmjNMsxME==wFhk=aSaz19iX4Dj8HBXqjhDg5aG_iR-uk7Cg@mail.gmail.com>
 <20201112125453.GM29613@gaia>
In-Reply-To: <20201112125453.GM29613@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 20:52:55 +0100
Message-ID: <CAAeHK+ycTa2nxg=vOVV_Sfn=w_883VRXYXE6Eb1gE=HXxSD8ow@mail.gmail.com>
Subject: Re: [PATCH v2 11/20] kasan: add and integrate kasan boot parameters
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VD7H2eMa;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
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

On Thu, Nov 12, 2020 at 1:55 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Thu, Nov 12, 2020 at 12:53:58PM +0100, Marco Elver wrote:
> > On Thu, 12 Nov 2020 at 12:35, Catalin Marinas <catalin.marinas@arm.com> wrote:
> > >
> > > On Tue, Nov 10, 2020 at 11:20:15PM +0100, Andrey Konovalov wrote:
> > > > Hardware tag-based KASAN mode is intended to eventually be used in
> > > > production as a security mitigation. Therefore there's a need for finer
> > > > control over KASAN features and for an existence of a kill switch.
> > > >
> > > > This change adds a few boot parameters for hardware tag-based KASAN that
> > > > allow to disable or otherwise control particular KASAN features.
> > > >
> > > > The features that can be controlled are:
> > > >
> > > > 1. Whether KASAN is enabled at all.
> > > > 2. Whether KASAN collects and saves alloc/free stacks.
> > > > 3. Whether KASAN panics on a detected bug or not.
> > > >
> > > > With this change a new boot parameter kasan.mode allows to choose one of
> > > > three main modes:
> > > >
> > > > - kasan.mode=off - KASAN is disabled, no tag checks are performed
> > > > - kasan.mode=prod - only essential production features are enabled
> > > > - kasan.mode=full - all KASAN features are enabled
> > >
> > > Alternative naming if we want to avoid "production" (in case someone
> > > considers MTE to be expensive in a production system):
> > >
> > > - kasan.mode=off
> > > - kasan.mode=on
> > > - kasan.mode=debug
> >
> > I believe this was what it was in RFC, and we had a long discussion on
> > what might be the most intuitive options. Since KASAN is still a
> > debugging tool for the most part, an "on" mode might imply we get all
> > the debugging facilities of regular KASAN. However, this is not the
> > case and misleading. Hence, we decided to be more explicit and avoid
> > "on".
>
> Even better, kasan.mode=fast ;).

Well, it uses sync, so technically it's not as fast as it could be with async :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BycTa2nxg%3DvOVV_Sfn%3Dw_883VRXYXE6Eb1gE%3DHXxSD8ow%40mail.gmail.com.
