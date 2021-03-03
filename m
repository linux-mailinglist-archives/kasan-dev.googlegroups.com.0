Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPMB72AQMGQE3QPOI5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 25DD432B7C8
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Mar 2021 13:27:42 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id n141sf13212346oig.16
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 04:27:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614774461; cv=pass;
        d=google.com; s=arc-20160816;
        b=oGGkiVv+kf8v3Pa3gC4/JMzA/T8VLaZR4emL/eEv3JdpBg7zfrcA6ZbkBlG4sOpJ28
         aOqz6NaE0TshO1HYqgIHelbZ6uDpID9BTXLpdHPIAotWx5ll+ysLEaYIrnRlqzBt9Kgv
         U5EHt2YNgc0AfZNFsC0uQr/SjrOaiTtNwi8Fx2s71jJDtlxFH0CFT6M5X54gKnadX6dc
         Qr0UX0tq6TNqzEGL0eJZjJdtzO7KA4NnBZ3Imvk123gDOxlHumEDNI6GjELFMylisr5Y
         KLFHuAsYjbIH7lCJcVDdQmyz+A7h3ewcK/Pk2GLjPxmv83HHFy4yLBt/vHs/KtlAo5Hc
         ANbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JPwXC7z1R9/g4N6RYfOSXyFO0vw+jMT41rZgiOIDIFs=;
        b=B9yQe+6kt8NYbXHp+qLPxWv1fvCx4fILrG3ANc8UW46m6wJz2ISDv1O4bRcEaMGOAm
         NlqKeObUzMT+CopPQUQhtWPfBVqYm0QkMD6qxpmM+PHDrGbfMgdIpKiv5MWAvJ1mu+yv
         gDfrskzLgh+LFpEcrU7pucXTNTdewxUvtOWHnygW77fhm7GKiF8CKG3Cor/FjG7xxSs8
         GDEmsVawusk224SIsv7LXbkWcoTqyAppn8ZfyPDXbkuT4Xa1mtLdqK/E6pTVzeQaaRCK
         99knVHTDF3ekITGCK7y1JZRGiYwZnbghiZjhbLlSari/tnz9jN8+g3Shlkv4Z61ajoMm
         UDRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I7GRODcA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JPwXC7z1R9/g4N6RYfOSXyFO0vw+jMT41rZgiOIDIFs=;
        b=Mi0UVJ8zntdoeY8HlIT6h3y1bQpqilo66fPSuls6Yyk4uM9yP1eo97WRixrPSuX/sA
         0kMaiXwtv2hlaS29bCz9paZtSsdsB3QCjGhI5Yc6kR4NwvVX7iFBtToiVCEnud+cXN2u
         cQIxiMVx9ewa5gOKmxGfWrUkBjO7qcE+3Ggb3aG7DcgAwO92E+3q9tHe9HmCwSnqSoQA
         ufsd4yRbJSr5W2lPOH5hLxYk/bnCplkRLLyLCNYY/7WUfwLa5BfonPztyaZfIAHY/2e9
         ArpUJEuE7tzqGdQWl4DYyHTO0U2tJRacaM/tjcr3vamVKVSpXZ0uga6m0+xg61FhH9VT
         FnqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JPwXC7z1R9/g4N6RYfOSXyFO0vw+jMT41rZgiOIDIFs=;
        b=ZKWpOzezaBOpmwmRIzK6m5IYfqqR10gZiKo6qr6It9RNNLJhlCaO8wYza4QDyJtW1a
         QqDgHusHupaNi6F67H26KssAqsSsbnmp0F2G2c2iFUPUbQ0R/OIxmGP4WnuIgS9caQVk
         i5ZIU5A0RUt8neDp9cqA6N0lS/yD20hyrBovOBWLvDOlnenBtqRElkF78xnv4KHig+/q
         6ZRWeERfAbVIvYaYO23+e2DBMhh6Pi6tzSr1tn8V6TiqLRqk3iU7/JXpPi+PiO50yIHJ
         oDANErXcpRnoKb6ET1VrXTbob/K0PRj0e9kwTj41CpEDnG4FHQlXq3MoKQgPqC3TR5+T
         Bxog==
X-Gm-Message-State: AOAM530vjhRL0/nMYF8AnDjYacHkg7EsGD+/IeQ43PCRIoNdM1XZnGe5
	aoZgjmaU0Rtl6W0G8BxzJjs=
X-Google-Smtp-Source: ABdhPJzE5io44imADzSj0aanFAmXch6C2IGeFKRJWSID/Go+ygrQWdHgGlruDQ3eAsz5ud4jfiMrOA==
X-Received: by 2002:a9d:4e85:: with SMTP id v5mr21440126otk.73.1614774461087;
        Wed, 03 Mar 2021 04:27:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:39b5:: with SMTP id y50ls556537otb.6.gmail; Wed, 03 Mar
 2021 04:27:40 -0800 (PST)
X-Received: by 2002:a05:6830:2312:: with SMTP id u18mr3429423ote.325.1614774460730;
        Wed, 03 Mar 2021 04:27:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614774460; cv=none;
        d=google.com; s=arc-20160816;
        b=XjFKgqma1XmtQmw+hleqejUlPfkvjauItvPXWmHE5qcvdIUDl9vp6S/8TFN5gVFT0M
         q7banJo6Qzs6RDve8Mv6VALRQhzDZFcQg3sdd6z3N7GgyGV2f75FMlUgqFm2wq0qNLoG
         jlp6aPi7gI4+8civlTvQLGMNJN5S33HRcRwlnFTwyOKJifLWO9MPI2fJZ0nd0wmfpsQ7
         fA53gcmXZ4jKLWJ1uiuaF7CXYsgxojAO6S2XgLTQtCqQdQBDXVfa0vtuOMXMTXkEX7lN
         Bk35cWrvtdlfKSFqwG70mq/S7X0SxecUxZ7tGrbkJsw6PeMAgr6y3paMuFd/MTxr5IrS
         PQew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mQJvPyDlOt5fHAYYg5Wntf4f/iXvZZKqmxZl2pA3ycA=;
        b=LMeh2zTRpVoiWPsT7gRHClPMIXfEFwXAvx52tylJ+HB8sIZnN+B/k67XnMf/J1a6g6
         P32lVDIxCfhygssfOFAHqqEfVSO+lnhGnKaww8hZcox28f4pgHngdzMRAHOo3Ek0LaCr
         64Rtr7T8QNoUzHF0xZIkJUi1jrQsAVB3P5nOtAOV4WP/58UmEfbMQYeWeg0D54BmJ3ft
         HYtbyGnw1LN48StaW7KTBa7oOf+B5+/+kZjuPdMm4AiFg/G0JvavStvKvZ8WOinyb7QE
         2Wb3eCSab0PZEuub3U3JdQmffEIMarhQYQkPWSBkYZNUtwAyHPaY8q80Qye17XAu6aCm
         6wDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I7GRODcA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id v26si1647877otn.1.2021.03.03.04.27.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Mar 2021 04:27:40 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id z190so23696049qka.9
        for <kasan-dev@googlegroups.com>; Wed, 03 Mar 2021 04:27:40 -0800 (PST)
X-Received: by 2002:a37:630a:: with SMTP id x10mr20824060qkb.326.1614774459988;
 Wed, 03 Mar 2021 04:27:39 -0800 (PST)
MIME-Version: 1.0
References: <20210303121157.3430807-1-elver@google.com>
In-Reply-To: <20210303121157.3430807-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Mar 2021 13:27:28 +0100
Message-ID: <CAG_fn=W-jmnMWO24ZKdkR13K0h_0vfR=ceCVSrYOCCmDsHUxkQ@mail.gmail.com>
Subject: Re: [PATCH mm] kfence: fix printk format for ptrdiff_t
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Jann Horn <jannh@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I7GRODcA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Mar 3, 2021 at 1:12 PM Marco Elver <elver@google.com> wrote:
>
> Use %td for ptrdiff_t.
>
> Link: https://lkml.kernel.org/r/3abbe4c9-16ad-c168-a90f-087978ccd8f7@csgroup.eu
> Reported-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW-jmnMWO24ZKdkR13K0h_0vfR%3DceCVSrYOCCmDsHUxkQ%40mail.gmail.com.
