Return-Path: <kasan-dev+bncBDLIXLMFVAERB5OSUP3QKGQEAHUQIPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 782051FB74A
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 17:47:02 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id s15sf15818455qvo.6
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 08:47:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592322421; cv=pass;
        d=google.com; s=arc-20160816;
        b=ghefYRUlEwekzi4xhLjMadYNcmUwW6IM8/khPPd4LEiZOxYJ+ufpknbm4DvBDy509a
         JLOtPtWbdkuY3wFDXTfxymXFmFkcoAeud7JsuqHDaiqSj5oVUnOM5PnNiVuxg1oll4NX
         K3NP5d8LO4YRtMMbzDWwEl+EITzoTDT3lvFTJesOXcBJLC+00ThVvhL+Q3RrepsEddMI
         /3FcCsPUO6C/b+SfiWMXphNK87HnTQwyvSHlXXEPhfC06mAjE06lSRJs/WcPVQ1SXay3
         BKWbORpYUnpPJ79TK7usXopHE1qqeLr+cxYi5kDuw/Gg93B2iYXEhBKJGQ1XMDCLE4JJ
         OxCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:content-id
         :mime-version:subject:cc:to:references:in-reply-to:from:organization
         :sender:dkim-signature;
        bh=k+rGblN7d2MHfV3gmbGlRyaisvceiv9qURdE4vdbUDA=;
        b=eOt+B4WnLG8PrOXzenCrHxW7T/vOe7mpCRrUrexFNYEPwtWNOUL3urVDWYIuOO8cZh
         uCfweYnKqJnqXzpbOHfeM7qJsc4eGh1nE8hfciGYd6L5SjB8h2c7uEBVAtMwII8GrBgb
         z6zVPa6pAUrqLhGlJwz9KZJozj3s7D76p8zimmoBkgpcp0JjdAdrGsIATqQQFBcmF8tT
         Pk5KrrLrflqXlxIwphRUAZMg55umtSU6YtQ6ffDyCyMewrGGJZMalzfUPyCWEjj11ip6
         MYG+RVm3qk3YgHnAzsREM4mSA3BkzSicIDAYnD1SqOKlOEmnDM75UbBUHWagUSpb0stH
         64jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=USu9EwtU;
       spf=pass (google.com: domain of dhowells@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=dhowells@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:organization:from:in-reply-to:references:to:cc:subject
         :mime-version:content-id:date:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k+rGblN7d2MHfV3gmbGlRyaisvceiv9qURdE4vdbUDA=;
        b=DCnXoDQ1EgX2RQa6l5D6hWSLUEWMZUtfSOY0qHu0ajBGhLhAqQ+aO/Wlm9fOGMXgI8
         lXBW9py1CuJdUnXGbeNYY/R4ZAvLcM5nRRWwTsiwKfhuUTsteJpbfa2p5U0lYrJwvMzM
         Dj6DdAu7mMzkedB2CpVnUm9SoQJiWPfdGqTdC0n3OtxvhUiKPWOwVL9UXpTPIjOvRm0N
         HSq2JYm2sVRl5R44+aKLx1ba4gCRa8tBrAlzZ6hUdxr36/3sHK7vi51mvUkmplxpBZBa
         Ttzc+6/7VctvT47t6d3NqH/00auFXLuf8AuSBRmDf67IfhN+CGo6H1s9/AzMbdm/iAuF
         GPpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:organization:from:in-reply-to:references
         :to:cc:subject:mime-version:content-id:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=k+rGblN7d2MHfV3gmbGlRyaisvceiv9qURdE4vdbUDA=;
        b=uFzYqsjWc9Q0qouZ+hSOsmhxIOLuPtpKoUzcSieF+RsJSJBJ7bpU6tv6k6KwtTbrZe
         VJJmJE5HI0mLGohPxTxU/5zZs5xlfywEN6bNBOdNsq95Z4g3056tvwU7dHKHmdCKBDNv
         PLJ90RpeAS5GsALS1MEl1WS8yMyu6TtGyctZwvZVn+alBwq8tfEHsTCvuALYC/zrFOQw
         8I+vH3Ym1K4F4fQ2/AZldJl82QeBZlt/M+DFIiB95c4XghTeYFv40tQGDp3FGW+EuwOM
         FbbUj9PfMBFdIwRznbpx5BvUp9QGetWztKYr/kqmC79Jayry8MUVa7vFHJ1YLN8HwXb1
         Lexg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qdFdfIDXxkLT/95IDW13lglqgpBG8peUZV7a5z7vXKJkZ8dBa
	tj2PejWkRl+zPAFgi3DKWUI=
X-Google-Smtp-Source: ABdhPJx1IFsuxXGFxoncSFS9PhTmRH7cHyniJPg+NXAMthw176HVsFfsWA6Gjv81hDuJhhmUXPGdSA==
X-Received: by 2002:aed:2062:: with SMTP id 89mr21472373qta.327.1592322421559;
        Tue, 16 Jun 2020 08:47:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e56:: with SMTP id e22ls6931513qtw.3.gmail; Tue, 16 Jun
 2020 08:47:01 -0700 (PDT)
X-Received: by 2002:ac8:4e86:: with SMTP id 6mr21715008qtp.390.1592322421270;
        Tue, 16 Jun 2020 08:47:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592322421; cv=none;
        d=google.com; s=arc-20160816;
        b=KjgIIc2bWPfvWaDhCbZZWB02M3H3NTnSdSMvLiVzFe976rElkUsmUodoj/YhTMU2ZY
         bK2HinNDeY1roob+0XSDxNZ/79Y5dYk1ynP9uIm2df5yW5V4BTZdHHLySBJ5aD96YE+x
         phJXh5d9rxMf1hHIUy+eoF6P9FmPKfRKCxwWId9nZto5LVH6EzfyKFBwMhKF97LCAqHN
         uxwoyvZObV00KznTenLEDkstn3Sabho8KOLnYJ+NATYNwUCBnEjNE+gUo2busGHewkVV
         j2GYNLRrnZkTnjAg5nX3OHoPBnDF1HVRZ4WCFUi4vMVPaVJBvWQwX9d7W4CiF2XGIClr
         HHyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:content-id:mime-version:subject:cc:to:references
         :in-reply-to:from:organization:dkim-signature;
        bh=djkgmBs6vxKrnF2svfHTCwO6iJZv0MD8YpKSjFl2MGs=;
        b=vJSeCSYfwTIt5Tum6s+/FunqbR9+kRCdk5Ptz51Oz2qisNuoh0k80rqL7sX+l4m3pl
         mAeFyWFa1o9ww8ZL7v4xfObt84nXnntrfxKsj7R3wjWhBFjOLiacM0ar8UiPlQH8GJw9
         S04o6M1dbMpqMVqCPw+6qRB9WQ0OUdWOuIL3+lVCFov/n6fyJhCsnBGtmSfth/F40+hK
         yf9MSliooVNuvl03yMRUqJyDJe+bF6GRgDffFjocLZIJi63N7P29EYIIOYIsUJmy0LnR
         mhq01jTDZj0wudPREHYaZjN10FPfhZSI0rxkSkqmSoKKk7Y63HriUHRCTJsFRQOvxUR/
         FXpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=USu9EwtU;
       spf=pass (google.com: domain of dhowells@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=dhowells@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id x78si825122qka.4.2020.06.16.08.47.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 08:47:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhowells@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-218-nWeeH7oNN9eY6skcHYs3nQ-1; Tue, 16 Jun 2020 11:46:56 -0400
X-MC-Unique: nWeeH7oNN9eY6skcHYs3nQ-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.phx2.redhat.com [10.5.11.12])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 0B3678DEEE2;
	Tue, 16 Jun 2020 15:46:51 +0000 (UTC)
Received: from warthog.procyon.org.uk (ovpn-114-66.rdu2.redhat.com [10.10.114.66])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 3EC3B60C05;
	Tue, 16 Jun 2020 15:46:41 +0000 (UTC)
Organization: Red Hat UK Ltd. Registered Address: Red Hat UK Ltd, Amberley
	Place, 107-111 Peascod Street, Windsor, Berkshire, SI4 1TE, United
	Kingdom.
	Registered in England and Wales under Company Registration No. 3798903
From: David Howells <dhowells@redhat.com>
In-Reply-To: <56c2304c-73cc-8f48-d8d0-5dd6c39f33f3@redhat.com>
References: <56c2304c-73cc-8f48-d8d0-5dd6c39f33f3@redhat.com> <20200616015718.7812-1-longman@redhat.com> <20200616015718.7812-2-longman@redhat.com> <20200616033035.GB902@sol.localdomain>
To: Waiman Long <longman@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, ebiggers@kernel.org,
    David Howells <dhowells@redhat.com>,
    Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
    James Morris <jmorris@namei.org>,
    "Serge E. Hallyn" <serge@hallyn.com>,
    Linus Torvalds <torvalds@linux-foundation.org>,
    Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
    David Rientjes <rientjes@google.com>, Michal Hocko <mhocko@suse.com>,
    Johannes Weiner <hannes@cmpxchg.org>,
    Dan Carpenter <dan.carpenter@oracle.com>,
    David Sterba <dsterba@suse.cz>,
    "Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
    keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
    linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
    linux-stm32@st-md-mailman.stormreply.com,
    linux-amlogic@lists.infradead.org,
    linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
    virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
    linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
    linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
    linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
    linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
    linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
    kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
    linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
    linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
    linux-security-module@vger.kernel.org,
    linux-integrity@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v4 1/3] mm/slab: Use memzero_explicit() in kzfree()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-ID: <879078.1592322400.1@warthog.procyon.org.uk>
Date: Tue, 16 Jun 2020 16:46:40 +0100
Message-ID: <879079.1592322400@warthog.procyon.org.uk>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.12
X-Original-Sender: dhowells@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=USu9EwtU;
       spf=pass (google.com: domain of dhowells@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=dhowells@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

Waiman Long <longman@redhat.com> wrote:

> The kzfree() function is normally used to clear some sensitive
> information, like encryption keys, in the buffer before freeing it back
> to the pool. Memset()

"memset()" is all lowercase.

> is currently used for buffer clearing. However unlikely, there is still a
> non-zero probability

I'd say "a possibility".

> that

and I'd move "in [the] future" here.

> the compiler may choose to optimize away the
> memory clearing especially if LTO is being used in the future. To make sure
> that this optimization will never happen

"in these cases"

> , memzero_explicit(), which is introduced in v3.18, is now used in

"instead of"?

> kzfree() to future-proof it.

Davod

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/879079.1592322400%40warthog.procyon.org.uk.
