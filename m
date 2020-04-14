Return-Path: <kasan-dev+bncBDH7RNXZVMORBCEI2T2AKGQENIFZI2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 696CC1A7015
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 02:30:07 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id np3sf11793924pjb.7
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 17:30:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586824201; cv=pass;
        d=google.com; s=arc-20160816;
        b=RISM/XalNhnbG86vWaeCofWX8ThONzyNI9oTXHSi/1x1sYHwWyAn2bwRMp8SS3gxcC
         Nbw5mTvua2onMH+rdc8yXuZPPORh6ZEJF0Eri5JxqcdU4Dc4UWef0SlhpLMinVJJLlYx
         swZzHHrBBDbey2Z2xNe7WXXn52Shgc80XVFka7IiNSNOCA7nTx2CU6d+e23nNRFBrwpT
         7IUW4fO3HimcOolOrZOWr4unI+TS/A8CtgPRRhPcVyVCGawPHdNO0XJCrvVnAB1bc1wd
         vSRW7YO2NhdX+PT5rMWW4DG2mAQLtD4CMG9SS8Wreo74y8IzzE+hVTDbmts/sPBSNTS/
         4Tvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :dkim-signature;
        bh=yygX2nvqCVT9Mu7Kf1raDdxfJJMRmbc2PqRM5y70uI8=;
        b=eSWBil1MPo6ZJmnUeGDWtSQ1AU3cz2LaZ/zMC5Q7d1qd+7wIrpogq7Mixvm5P5/MOK
         FpBVYsE9pr53zk5X1OMulAO46PuF1kzPoTU3931FXenSzmRknQFntidtUCxhcbDnJxiC
         yV9QugRsndpdF0ZCu/CMDObZVuG09DsdCOOLMti/t1UvR7hICaa1j9FyIDpmMOU86MzY
         989ym4XkqFXAJ4kIBHRNSOQISwrFlJpFRXmlmhiS07C6VsBbq9cDm/5utp/wInF5Se1f
         2OCuT+XilZnJEIYRO0wUKvlrou9FrL3iy3OsiDG6l4q6lakmHAX19NwvjX4NEQJa+TUL
         8Tsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PMRE9MFB;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yygX2nvqCVT9Mu7Kf1raDdxfJJMRmbc2PqRM5y70uI8=;
        b=BTxOb3sua5vl/l+KH5EXtS+cjnS0mE8mGd0knYBuOe6nVUV7OKK0uY1tSlIvM2UUmp
         xO6a+F1+MQxVfk9fjrSSzCiRfcxMIBOkrbjrtEgDNDZyBHWA+vXPuCb6MLWmn6QJCKIR
         c0QzCM4m1UQx93KfipiRDPAoNK57GQL8beVgtTA2yZ5AtR6nhB6bbjLZHWajX5uTrHCh
         dEBDZuxQEjuf3gPPqgIbEdsZV5BFHB0o7OxrD2/d00+jotssJQm3ton+B15S0Z1GHazw
         BNC/7zbBVEYcwo+GASjv0yMnNtkuP5JeECANDCgMpwY/gbrSdIA2CHzSKRHMs8zKW43J
         CFBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:in-reply-to:message-id
         :references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yygX2nvqCVT9Mu7Kf1raDdxfJJMRmbc2PqRM5y70uI8=;
        b=U80ZNfVo8St0uZlgaSPwErw1fxslJewY4976xRxJumTK5t0Fm0lUhOPXlFqhE/TWFk
         9XhpMnyuRxcC5hnKT7BcaMY6M9EmpLhXsZAgWm7pp+AMjiNt6d2xzHA5yashllRmM/eB
         iPTmNKUXNnrZSITndhPnnHvBjY7RT0pknwycJ1kV6WEYa+O7V6jjzFH9W03zrFlrkxtu
         MlOpHXKmCBT1XVN0fhl6E3e6Lbx1cYd4/Y8PBVROCSMUYE8zV5FQqYhcGqf/C8odriH6
         paeSusWuKjgUXo6PHCOWn8g8tMhm48agPw36H+JFS4X+1Z8SDsYZdTeV9L44s9+gVo6S
         vV5w==
X-Gm-Message-State: AGi0PuZcxU6ComCpjli9VXAE4mTsiiRWFIgtONiLlhNrFxB3HapiAtgD
	vPVWZP9ZSJMElh5/uVzr/eo=
X-Google-Smtp-Source: APiQypLssRI0+nUllBH8juTxv6Mr18ehVjQsENO8/y6o+nUhecie1IHOJgFRZ8Tyrd08rPLLAVVd2A==
X-Received: by 2002:a63:7d43:: with SMTP id m3mr19438352pgn.193.1586824200969;
        Mon, 13 Apr 2020 17:30:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:32f:: with SMTP id 44ls2547806pld.1.gmail; Mon, 13
 Apr 2020 17:30:00 -0700 (PDT)
X-Received: by 2002:a17:902:8d86:: with SMTP id v6mr20240111plo.57.1586824200414;
        Mon, 13 Apr 2020 17:30:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586824200; cv=none;
        d=google.com; s=arc-20160816;
        b=U/j2gxA+e6Sp1p5T1um9a246BSJaXXemZlKpLDUj4o7MX7WjNrXlqVs0d6N27HmhT4
         jxkXFnpn3BmryfYzVW5QlzS5N8oOvGDiN+c63XcWfBn3Zn17yy27NbwUVUT65cGarQU3
         BYQ6t6ZgI1nE3Xl+KrrU4luyJiJ4MeOR+9kZuO3VUMUKViVGTGMVT70pdYdGPYuJwc9q
         eWYUyA42AAPbZIWLkrhn/GvQ0dt6b3T15zgyycbZFyuPnAhKeTQP0ivOUjAyt0Iqe4vb
         fMI8OcbAZFlQZHu/zvAxMnJVenfgFTM6qrTW1HMyMnfiWJYo4RslZiuZwTi6x0AgGAgR
         22qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=GtP40NBc6K+wY7TevCqJVJVyGGxw6eyhk3x6njvRZbI=;
        b=yrHbmTqmm0KR5jdbWkr4SIu/x0OkyYOysqoCaHjK4NmOqht5QvH5BbO54eya36c90R
         OHazSouWvs503mndCN+D7L28mMH7QrU1quK4jUlSCwyC5gui+9ddmqZNQk+qDi4V3hZ+
         rJGM/XZibiJ11zphdfYtMU/IEoRIwyH0HiQfYQEkZPbXJ2zzHX/qJb6z9hK5mtYyg8ow
         CAXa6FT7g1RfwsxLeJDmM3xa8nA9IAjHxosw6GwWggrZvZvgDsrPvrBWH8IK6mcT1kN1
         5uuCT6eeulFzUFEPsmmMHplE03a1IZcbUUPxBz0wQHgozXg7cFOqHwDJSk3KH3fAkce9
         /hqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PMRE9MFB;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id q15si728081pfg.2.2020.04.13.17.30.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Apr 2020 17:30:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id r20so3624529pfh.9
        for <kasan-dev@googlegroups.com>; Mon, 13 Apr 2020 17:30:00 -0700 (PDT)
X-Received: by 2002:a62:dd48:: with SMTP id w69mr10144721pff.86.1586824199909;
        Mon, 13 Apr 2020 17:29:59 -0700 (PDT)
Received: from [2620:15c:17:3:3a5:23a7:5e32:4598] ([2620:15c:17:3:3a5:23a7:5e32:4598])
        by smtp.gmail.com with ESMTPSA id g11sm10055136pjs.17.2020.04.13.17.29.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Apr 2020 17:29:59 -0700 (PDT)
Date: Mon, 13 Apr 2020 17:29:58 -0700 (PDT)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
X-X-Sender: rientjes@chino.kir.corp.google.com
To: Waiman Long <longman@redhat.com>
cc: Andrew Morton <akpm@linux-foundation.org>, 
    David Howells <dhowells@redhat.com>, 
    Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>, 
    James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
    Linus Torvalds <torvalds@linux-foundation.org>, 
    Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>, 
    linux-mm@kvack.org, keyrings@vger.kernel.org, linux-kernel@vger.kernel.org, 
    x86@kernel.org, linux-crypto@vger.kernel.org, linux-s390@vger.kernel.org, 
    linux-pm@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com, 
    linux-arm-kernel@lists.infradead.org, linux-amlogic@lists.infradead.org, 
    linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org, 
    virtualization@lists.linux-foundation.org, netdev@vger.kernel.org, 
    intel-wired-lan@lists.osuosl.org, linux-ppp@vger.kernel.org, 
    wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org, 
    devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org, 
    target-devel@vger.kernel.org, linux-btrfs@vger.kernel.org, 
    linux-cifs@vger.kernel.org, samba-technical@lists.samba.org, 
    linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org, 
    kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org, 
    linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org, 
    linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net, 
    cocci@systeme.lip6.fr, linux-security-module@vger.kernel.org, 
    linux-integrity@vger.kernel.org
Subject: Re: [PATCH 1/2] mm, treewide: Rename kzfree() to kfree_sensitive()
In-Reply-To: <20200413211550.8307-2-longman@redhat.com>
Message-ID: <alpine.DEB.2.21.2004131729410.260270@chino.kir.corp.google.com>
References: <20200413211550.8307-1-longman@redhat.com> <20200413211550.8307-2-longman@redhat.com>
User-Agent: Alpine 2.21 (DEB 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PMRE9MFB;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Mon, 13 Apr 2020, Waiman Long wrote:

> As said by Linus:
> 
>   A symmetric naming is only helpful if it implies symmetries in use.
>   Otherwise it's actively misleading.
> 
>   In "kzalloc()", the z is meaningful and an important part of what the
>   caller wants.
> 
>   In "kzfree()", the z is actively detrimental, because maybe in the
>   future we really _might_ want to use that "memfill(0xdeadbeef)" or
>   something. The "zero" part of the interface isn't even _relevant_.
> 
> The main reason that kzfree() exists is to clear sensitive information
> that should not be leaked to other future users of the same memory
> objects.
> 
> Rename kzfree() to kfree_sensitive() to follow the example of the
> recently added kvfree_sensitive() and make the intention of the API
> more explicit. In addition, memzero_explicit() is used to clear the
> memory to make sure that it won't get optimized away by the compiler.
> 
> The renaming is done by using the command sequence:
> 
>   git grep -w --name-only kzfree |\
>   xargs sed -i 's/\bkzfree\b/kfree_sensitive/'
> 
> followed by some editing of the kfree_sensitive() kerneldoc and the
> use of memzero_explicit() instead of memset().
> 
> Suggested-by: Joe Perches <joe@perches.com>
> Signed-off-by: Waiman Long <longman@redhat.com>

Acked-by: David Rientjes <rientjes@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.21.2004131729410.260270%40chino.kir.corp.google.com.
