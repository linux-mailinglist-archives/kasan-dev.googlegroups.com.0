Return-Path: <kasan-dev+bncBDW2JDUY5AORBXPR2SEAMGQEEOMQHZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 97C753EA716
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 17:06:05 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id q19-20020a1709064cd3b02904c5f93c0124sf1927514ejt.14
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 08:06:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780765; cv=pass;
        d=google.com; s=arc-20160816;
        b=A1oox/OZ67RRvO/pSbHsrgwmb/YngL5q9aG7dJlhDHa5RqWu8KGnSj0lH18Qdu6L5o
         asa6XWCx07YLF6Xa7u+Drmnx+DD+w/Y8/oNmcDNQSA9Wmsr3qcKZX3OBF2rtg86Frq75
         d7aNhM3BI1YE0Ns/UBZnbV4/axnb8pwl+g+GI7E5vhcDcfaW8YramYk7+cAfBvAHD0fv
         mJntNuEXc+ttBMgIL6sBshoFRTMGVxdDXlYmKbdYijnnYA+8xNvfEs1bVguG3F35Nzlp
         N/bE2kwZLtdCAqBRylIVHb/L43GFTbk3RBlKvdT24X4ofFwgTG9AeIL9CG83Db5vmDfS
         nJ1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4cfsGJnWsgHbeRaxAxp8Rx5Hw4G1Rkbn+rkk+bZL4wk=;
        b=WnrPbKVP01tCWtd9EcrkghmvNJVPb0UEHX6t+C9qAAoBZfIqT0TumNACuJb5q3NSSo
         Zbjnx96v6lKFUGywmy6x7y3POn6J7QJliDoBOpSI2Yojd4ptD48EQBr+RCXOEvk3d2Bv
         se9RHYwZJSfsakt1I+YKaHrwY0HOL438FgWpxACYiJRHKSlsQmc2zX+pS9YfhNWEgGR5
         T2h8fCE3wG5W8eGbKbu18ZK8WukHLt6+iB8zQ4pTbqA4GThx/5HCjLElD5zuRTJ7kMzJ
         5Z2U0MdFjt69lz0uTk+OUomtySkvcLrBesVFb1KUenZIxobqdO08G8Sv9/Jc+t2osd+J
         hnhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=KaHfVQvX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4cfsGJnWsgHbeRaxAxp8Rx5Hw4G1Rkbn+rkk+bZL4wk=;
        b=WGfr7ilGTz+6zvJEQHFmE+O/3w9iFW75KpWHvZ0rjxdWxD8rNzYdwwyqvvThSrRKqy
         wm3nAMIgRcfZ4oY+qZYSNammpfyu7Fxu8nYXSiFxz45brP1KqrwT0W+Fbx+3yQmZofn4
         T7KYfkr6Pluh1p3o60+Nf6jEfb7HreT9z28I52T9gxemMeXNYN/bxgoz4CA2jY1Tr6E2
         4n/HjKavW+Nn0YmHOQSTl/NRysOs+P0QLsrtg5sg9+Evt4iPoI4a65HMKaXkidChjPJZ
         htuU3aVlhu23GNHJ0BD8AdzwLCybUgbfGnkanBJeeK8dRyqvll0WRvNTmzJifzJeuKnD
         r2rg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4cfsGJnWsgHbeRaxAxp8Rx5Hw4G1Rkbn+rkk+bZL4wk=;
        b=PfxlYFFoaXYpjalb4xI7wUhGhZ31zL0Sk5zEFsOoqrrTOi0hAv0Pf2c60LmwzbAPIO
         5oyJUCMuC0qK5femaIkYjxhqERWpx1g3el/ejYpgYX8f4sysf/PZQW9IaiRnNhCkEI2z
         AkmFDuV85nonn+xGUfO72nXb/4HoK3DmUgGx8o1m7YvXWuKiCzBYEvvz5gX4ejHgoxhq
         JN4B9DkrtCOQspn96N9IHg2QGho+1tLanJ8aOul/2PdcZxf36GV26NYxQ73t0BACJAoG
         SJTcUCMd7IidYKv19L2mV23+kZ06D49sN3onuc5/P4XW7XVF0JYj4pJiF6IlP2wfwCt5
         m4WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4cfsGJnWsgHbeRaxAxp8Rx5Hw4G1Rkbn+rkk+bZL4wk=;
        b=tSAXpn7L0hswFUl0yyVpsQBGg/BSbJX24FQz+Q4NeE/KffPWzBmEIzNV7BoTK8tmpz
         6ILBHK3u6pccT8b+wgCOV+9QmdHL8wV5Ec1HYEy05T+SkEi2NOPiDz+6NKuDjEPT2eIR
         oU9fJ8TBS+AWa+EOMpYaib523A6+DxZhQz/T753ETFASKvwLCp+dsuJO6t3eVD+RVhQe
         7gfTzJHT20X/0L2ugPb/kbFZEewnSoUBgq6b9wzmBd0lDsoeMzUJm4nhkoEmFF/d+DKZ
         HNs/WK+rtD7MMIhc1Vs0FCf2VU0vwDR8GwHK3ajZSzXEO3fcpMQsfAEHBMHcESgCos1r
         yV9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cGYb50Wet3darkRMsHY6jn4Mr4Dw7TOzSMx4X1xD4H4CkyAvX
	afZBKNMONy7Kcr37K9EVtDg=
X-Google-Smtp-Source: ABdhPJz3BI8qysJfK0ZrATWdj5l9sRsnlj1BTLkNyZ1UjZYTfwJX22pZ5s5Fir8/+NvHjutaJ4s8RA==
X-Received: by 2002:a05:6402:408:: with SMTP id q8mr5969182edv.13.1628780765365;
        Thu, 12 Aug 2021 08:06:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d2d6:: with SMTP id k22ls7071120edr.3.gmail; Thu, 12 Aug
 2021 08:06:04 -0700 (PDT)
X-Received: by 2002:a05:6402:3099:: with SMTP id de25mr1332086edb.36.1628780764424;
        Thu, 12 Aug 2021 08:06:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780764; cv=none;
        d=google.com; s=arc-20160816;
        b=nSxm+VBUTYzfOe6S+sC7MV3VT0XHsKLZUPsLVWnJGutw5RfGq8n8a/8KfR1LsSlMDs
         1XnAN/ckgtorgQ2AIylhsxddgNjsGHTuy5//I9QJ2fyunaDwcRVa+4qxMeaOKkJtmQ3Q
         FC1GOZNas1j3X7Vi7oGYKM7TfxPXtTCUPJi3soGENdve2EhyCGohKgwNXZvMvO+sUuev
         QKQN+w7CTReG3TEUSv/fWD/mkb4UNbWiwg6j5CeEC7fXbfdXy5QHkfjHo+vAQwpAqQa1
         1q/uP76QcgsBH2oxT9Ca26rjmgyQbMbzQhANzUwOwW08Q35b+bjiW+As70zMXqKV7Fqz
         H9qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QEmLCQfmQOuhAIlIo7tcPafee51VNGzdqFJimZNT+qM=;
        b=jnpQiUZ9hiF9tn03B72Obv1XQrKIY+FtbHxz1gCJ2IVyQu7E9oYch+SZZWpCCuvK9+
         Lmu68MoQUwH/eyR9QD/HfvBCjfX1gXSl7uRnwgFyeJNaBsevqg0lspFbr/HaJNFN5KnP
         LfhKIamkSmJvZS/Lln3fSdBK2Gj4qRgYbu5Ea3Lk3FD8tn/lVTYKIxeTEfWjnUSaF6p6
         AoPHonz2BhP9gsDjDdheXm3gZkN37BcPXqQlcP9q0rRi9dirkFP4UODprmhAxorG6fWh
         LZPwqm+Fr4mckvrBOr8Fu8iMlVxTOJtujavNFQOoWPJ4PCmGdVkDoFc212tyGJUng2pH
         uuRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=KaHfVQvX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id s18si238373ejo.1.2021.08.12.08.06.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 08:06:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id q3so6083904edt.5
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 08:06:04 -0700 (PDT)
X-Received: by 2002:a05:6402:1299:: with SMTP id w25mr6232247edv.30.1628780764189;
 Thu, 12 Aug 2021 08:06:04 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628779805.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628779805.git.andreyknvl@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 12 Aug 2021 17:05:53 +0200
Message-ID: <CA+fCnZfjsfiAsfnOxJhMaP0i7LaDgsVSkrw_Ut66_E_wQ3hE_g@mail.gmail.com>
Subject: Re: [PATCH v2 0/8] kasan: test: avoid crashing the kernel with HW_TAGS
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=KaHfVQvX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::529
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Aug 12, 2021 at 4:53 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> KASAN tests do out-of-bounds and use-after-free accesses. Running the
> tests works fine for the GENERIC mode, as it uses qurantine and redzones.
> But the HW_TAGS mode uses neither, and running the tests might crash
> the kernel.
>
> Rework the tests to avoid corrupting kernel memory.
>
> Changes v1->v2:
> - Touch both good and bad memory in memset tests as suggested by Marco.

Ah, I forgot to include your reviews/acks, Marco.

Perhaps you can give one for the whole series now.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfjsfiAsfnOxJhMaP0i7LaDgsVSkrw_Ut66_E_wQ3hE_g%40mail.gmail.com.
