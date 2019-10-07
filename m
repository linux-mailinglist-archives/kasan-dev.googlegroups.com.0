Return-Path: <kasan-dev+bncBCMIZB7QWENRBTP55TWAKGQEKOVMA5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 994B3CE3C8
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 15:34:06 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id e15sf10086427pgh.19
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 06:34:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570455245; cv=pass;
        d=google.com; s=arc-20160816;
        b=tpaHZmmRVPHhdGYWRhUxTHy1kOmdb76fmJFfsBmy4zJ6Fu/UewiYu7wDynqc78QZqI
         K530J85YT0XIFxtFbMpYm/iNnGoja9aRaSRoPdZrC7ZlKa/AusKZ/pNwlkre0fBZRwb7
         BnNwqpkeuVM33OD8Vzmw3/noWwQa9022KTlCvY2QqFB1i3UFkMP/vLN3jzqgGynYH4QB
         vVsXkgMdfSnw81xj3eS8SZWloNwLV2sUmQNSIm4owKpgkyKIemGBA1u4zSgPUNx2HXgf
         j11O0j6tm1YZ3NpKjLXRezPjDO4Owy7KD+PX1qdgBXjSzyDv0CJRz5KgUCGFGUFK0n62
         Ujcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZKq4BNYM7lbwslBY96fS7OMil7ccPxzCiCVLbELtq3Q=;
        b=hyuskcVADplxbOl0o+B1vXdjsgDpRtAOwnivo/QRNi0oGXaCTNxgh3MdKy9BflavS4
         CFNi/6WTuN7orrqEHoIICWXMbXFTO08xF9Xj/WjX4uoMjDqmTc7DpuEqKWhiHw5QIUZd
         84ERxY+PotCsORIg8PuIBMa0J5R0cN7kMRexHtt7KFzCwicnGQE6sRW0fhSMUuvnNza7
         YND+kkL3rx45+Q9JcJOPAPFqnzc2fAz598esuYQOhdHRLW5pb25by97tMEXKftotA/B9
         AaWwEh26/RLMVsPt96r0srkaShGUECRU3eSHGMd7r0TDqtryLMfykQplqT2NsBVJqQPC
         vPAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LpR2u7B9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZKq4BNYM7lbwslBY96fS7OMil7ccPxzCiCVLbELtq3Q=;
        b=ZrYh8vbHoK/DIPc4wC3IaYnpWXaf/sZf6kYM2QnFpsk0+jFw1sMdVWTecGtXg76fjJ
         pcGURrGG2/4w+4i9DQ9xh8Pj+Ac4/C1dr871Ee8vjbcaasX6DfZHO9b5PxhGTIqnUdI9
         VHvm1pUtIlxZlS2p/2KY5SC4h/cp7qWBRumICDv4PApENE9GmHOTukOpHW4riXS9Etnf
         /p6DJ0HdQxUYybsZ3DxlJwwv1BdVSA6iKhbo7BWUOacksuotOJZZ/zMOLFWvwyRDfpHs
         aC+ao/VNvSyLUDtYDcirVWBIWTNx03V53dyq0Z694C9f8RdrdrKR2B6NT1HATdFGDysP
         2AiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZKq4BNYM7lbwslBY96fS7OMil7ccPxzCiCVLbELtq3Q=;
        b=lotSKnj4mfAt6RYwSWbYIgV4baHhmkJyuZic8oi+ah3IYj3Xa8EuCTp0ylCR/R7KfC
         fcngxZ3igzFmJ1TkeTLhYZgIgpS119Vj9z8XH48EsJt7k7wexJKYaKizUMb23vbHqcbK
         jXm47trJ/loWL1dNxCJ748JOPwB3k8B9DwSM5L7bK7fGi/IEm5IRAd6OppnD3Z3JySoP
         Jgtx5Lwh/rCeSJgLSCykDEFwTWGn2i38ey5l5hD8m1Lc0aDYJhgUqj9M29BrENkLMxt3
         kL3LKivi18OXk6Mon0HLIZNTnp8DqG1IiIVvEAFKV9W9CHzRIC5fssioT0/h6LzvPqsA
         7ZJQ==
X-Gm-Message-State: APjAAAWpUgK9IY1ME7BZ2WY8hdGPEiEvNDrTV0I/qMPiAYtFQlDcwe/z
	qRgF1oQEco+l/qFKC1C3VNc=
X-Google-Smtp-Source: APXvYqy5pKg7z+fFurD2mw6IJHPJMvjIVOgxz2Lbdd78/8+QaiHJwRvRYHgl7V3J4dq9uQf2wyuEwA==
X-Received: by 2002:a63:e14:: with SMTP id d20mr29946222pgl.33.1570455245047;
        Mon, 07 Oct 2019 06:34:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:80d1:: with SMTP id a17ls14280pfn.7.gmail; Mon, 07 Oct
 2019 06:34:04 -0700 (PDT)
X-Received: by 2002:a63:ed08:: with SMTP id d8mr31589251pgi.239.1570455244438;
        Mon, 07 Oct 2019 06:34:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570455244; cv=none;
        d=google.com; s=arc-20160816;
        b=qtgua8aN7+O3qwuvddoqU0+cVkmZ8wwXakv9eYqo1vN2WTgc3CZ+HlSYWc8pPc1Zzv
         l/HgxQGxfeYRmc9yZ5n9eiEeTucJEUbXIxRzvA6OazueCYVAMggTJJq8rJPX+WJoIrgZ
         MlefekOvvg7uS1TD0jiQpjrB/j0Go5FEF7/k7wzdwMueT1QtIPhtu6crNqbN11WXXhMd
         f7hhO3bZiBA3MkppvM/kcatrnxWjwDx0c/8KrgMtpHRX58cwS6yNKF0lKf4mgl5Kzbqi
         bq6rf1/0CVpHz9s0LrS2rmFYZVlXzzBO3AmBfLgSSQkBSLNEf6Qe/0Z3f0TY41D3LPAD
         X6cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Nwlp1QPq4c1Fg6asQ7NB8TWNONjREWmPa9T7sJeo1Lk=;
        b=ogIghmoueZKHQkzyUR6mcl5wYSyIArZv9leqM22b7IIoV/cJtV2BXNop6zmewcACA8
         cQ07EE6J/Hmo0OMZDMZy0ZpwVgYzuplBL/z66B1dnDHAonUD3dYuGugshQnjAb5MwOgd
         5j3WEakvjzL8NsD0fSc2tf2QACK0B5RJK8uqTfwa9U0plQr41CapVKB4Co5FSOKVvxUk
         KSYAdsGOSAO1CIl46H1IgWv1ZDl+btjUt2UlXq1BdRAkKSGxNfQIBzRR/xIk13+4neWR
         MnoaQeW1zdElMvprs+WvB+ncCtxkTCzTlsKHSXtANr/DKBU9Btfhfm5DUIS3bw/1O95N
         N6HQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LpR2u7B9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id x13si366654pll.1.2019.10.07.06.34.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 06:34:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id y189so12563250qkc.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 06:34:04 -0700 (PDT)
X-Received: by 2002:a37:e10f:: with SMTP id c15mr22691586qkm.256.1570455243666;
 Mon, 07 Oct 2019 06:34:03 -0700 (PDT)
MIME-Version: 1.0
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
 <1569594142.9045.24.camel@mtksdccf07> <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
 <1569818173.17361.19.camel@mtksdccf07> <1570018513.19702.36.camel@mtksdccf07>
 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
 <1570069078.19702.57.camel@mtksdccf07> <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
 <1570095525.19702.59.camel@mtksdccf07> <1570110681.19702.64.camel@mtksdccf07>
 <CACT4Y+aKrC8mtcDTVhM-So-TTLjOyFCD7r6jryWFH6i2he1WJA@mail.gmail.com>
 <1570164140.19702.97.camel@mtksdccf07> <1570176131.19702.105.camel@mtksdccf07>
 <CACT4Y+ZvhomaeXFKr4za6MJi=fW2SpPaCFP=fk06CMRhNcmFvQ@mail.gmail.com>
 <1570182257.19702.109.camel@mtksdccf07> <CACT4Y+ZnWPEO-9DkE6C3MX-Wo+8pdS6Gr6-2a8LzqBS=2fe84w@mail.gmail.com>
 <1570190718.19702.125.camel@mtksdccf07> <CACT4Y+YbkjuW3_WQJ4BB8YHWvxgHJyZYxFbDJpnPzfTMxYs60g@mail.gmail.com>
 <1570418576.4686.30.camel@mtksdccf07> <CACT4Y+aho7BEvQstd2+a2be-jJ0dEsjGebH7bcUFhYp-PoRDxQ@mail.gmail.com>
 <1570436289.4686.40.camel@mtksdccf07> <CACT4Y+Z6QObZ2fvVxSmvv16YQAu4GswOqfOVQK_1_Ncz0eir_g@mail.gmail.com>
 <1570438317.4686.44.camel@mtksdccf07> <CACT4Y+Yc86bKxDp4ST8+49rzLOWkTXLkjs0eyFtohCi_uSjmLQ@mail.gmail.com>
 <1570439032.4686.50.camel@mtksdccf07> <CACT4Y+YL=8jFXrj2LOuQV7ZyDe-am4W8y1WHEDJJ0-mVNJ3_Cw@mail.gmail.com>
 <1570440492.4686.59.camel@mtksdccf07> <1570441833.4686.66.camel@mtksdccf07>
 <CACT4Y+Z0A=Zi4AxEjn4jpHk0xG9+Nh2Q-OYEnOmooW0wN-_vfQ@mail.gmail.com>
 <1570449804.4686.79.camel@mtksdccf07> <CACT4Y+b4VX5cW3WhP6o3zyKxHjNZRo1Lokxr0+MwDcB5hV5K+A@mail.gmail.com>
 <1570451575.4686.83.camel@mtksdccf07>
In-Reply-To: <1570451575.4686.83.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Oct 2019 15:33:51 +0200
Message-ID: <CACT4Y+bJFoQPJ4QbGNjAuqiZx-FFsuLansxkhX3kwLOc19NvcA@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LpR2u7B9;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Oct 7, 2019 at 2:33 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> On Mon, 2019-10-07 at 14:19 +0200, Dmitry Vyukov wrote:
> > On Mon, Oct 7, 2019 at 2:03 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > My idea was just to always print "heap-out-of-bounds" and don't
> > differentiate if the size come from userspace or not.
>
> Got it.
> Would you have any other concern about this patch?


Last versions of the patch looked good to me except for the bug title.
The comment may also need some updating if you change the title.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbJFoQPJ4QbGNjAuqiZx-FFsuLansxkhX3kwLOc19NvcA%40mail.gmail.com.
