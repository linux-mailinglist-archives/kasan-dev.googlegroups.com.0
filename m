Return-Path: <kasan-dev+bncBDW2JDUY5AORBJMN4WJQMGQEIKFKLJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EF455202F1
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 18:51:51 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id v10-20020a17090a0c8a00b001c7a548e4f7sf10844032pja.2
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 09:51:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652115110; cv=pass;
        d=google.com; s=arc-20160816;
        b=P9ddBBvCRiBdAoGRluClvXSXfOYBUrEICCaCwFH+O/NNL2DrfyyZLkpIDqSYl+AB5J
         0qTs4wGyEfqwlaj0lM/nc6Q0yZXvLy29es0Ar3GP/978DZqjJ4M6eYOFPEq665VKnUW+
         oza6YxuwqIUk8/qUrduQQe21LIw0zN5+VsZif/ozo/L/9lhiUA6VCn0XwBpxpDKb/JPt
         +dKGJixjBTMwbOzAI3vNjYB5g3BMNrWqW/8rYb3zcc7+wekNZxX3l0JO35ykUIqK6Dqa
         S0Wqv9jB+phD6u6BGikqi1obE3acb2Rx0o1lrVG8WrGJTaYp7gJBMm/eKeZofYkbZ5K7
         zAZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=Yo1EeCWLtBTj5bl1cOTZmx4yFS/WH1z+r10Bchjf5Tg=;
        b=jcKNBAS50UMGjA59zHBUxZH4OkGy2QEdT9DCgRA7dFcZDDxClVmBBPFScj45pvyXnZ
         CMiWF6Y6dyUE1LHv2a9bn7RYIzw/f74vN/yBuB8D2C2r4i3sRv0s7SABY3ex8rNBd83a
         wY7OV9vFzLosmPIjpmWx/gVcBkGNuV7QSjVZntFs+mqgr8bdtaLo7mceZH5Lckc7I6PM
         0j3igqugHKiSkNiTJlpm92hLcpnVtg7x4yXu4Evr2s3aj2pyj+Mwq/75xMF4EfJm1E+z
         TDu+DV9rLZ6KRx2Hmd3WgNljQHB7KG9GMRhqFyKSGq4ICLIxrCPXQd+67W1Hh+zB1IQe
         p9Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mPniJxZ6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yo1EeCWLtBTj5bl1cOTZmx4yFS/WH1z+r10Bchjf5Tg=;
        b=nsmOusdGLBcjDvOswGiLx54sON4zeuUQIZnI+aJln4zP0xVb7xoZsRonZZidOIu/ba
         BISi8YByBUrBEd+c7T1eyrltJqSp7rlKCkq7z0TFvE5WQttim+RJERMT8TSA6g3SpcSV
         Sx720pmfFBfEHbVpP4Jx9UfAUtDPocDpCMPf+N7ccWo8I1Ho3Klu1pNlQNyVJtabFb2B
         cc4rRpBKWJ+k5fimGZkfCKfwnh3zQdP+tnuYZq8oLYWndpUCScwVieVDu+LSrBf1sZDH
         TY9TX0AIrYvSWrnCQdE4fwB/suwURuTI0MyQJhFJGqQLdAKDEldxQsxB46ht93WiZVUS
         +gfg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Yo1EeCWLtBTj5bl1cOTZmx4yFS/WH1z+r10Bchjf5Tg=;
        b=n69QtivK+utAC6phSIz643in05gI8sOdqHuip9e8QXmMJ3o3i2/SmJHpdVW9I+bQwD
         O9hHkCOoMK4kuhKQtfjOw5CJcnKlg8Xvtr1nvlnWcdGjgqqlPAA8A3SdqBeZMR/I2Ci0
         4J6ozWH6IWGUDWFJ1QKEqRcpNpw1aSo4J8bXyicp1983ywISNibxm5fuYQtBJyfxeHmF
         M6C1YAq7XOZs1FTu5cAElfL+Py/Iy4gvrCkw0OC4Fev8twsFnwY6Nahw1W7mceXezLuc
         l/3RosQyWCYtvpAJa5jAnk4DgXY2oC/L1/y4bKa7nX8ebyQne9Q/Gts9Lm5OQBXrblZp
         UMQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Yo1EeCWLtBTj5bl1cOTZmx4yFS/WH1z+r10Bchjf5Tg=;
        b=XDS+8KHU0USze8TvguLLFuxUF9hWhi6oFHNa6GR4t0ohHFFUtEr/irpEYBw/cNOVRk
         BNowKURoMdE/eekR9qCy08oGPSIsYwdvljHt/xs5l3ba+i30hSmWbS2y41CiIENzBu6X
         IBkuOJxxy59nWvvNwL0GYi2BnYsiqbSEVJOkPrIhQaU1RKA6Fro2+BEHidufHZv5X9O6
         D4B6cZPllJ5l6waEXc2K013wJJTDiT+0mYvOdN3V9XQWk3NSWrGTrpZ+jLzohiZm/wVW
         aQp87yy4mQY1o60YPyRUijgwf8/tETjiCUYc4vNizw/NC0pRpeLKMtEnHNH0gvNk2nUv
         mFRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531kHS2XvYKLqtvbhZdd+OQhB3kvK0EhoYWuirOd7N3yXaHESJSk
	LcU7DgDQqAG1cA1m09L3Xvk=
X-Google-Smtp-Source: ABdhPJyRr21KLmr54Xsu5dG1oIujWl1747ZV33yzs4pP6FyMYAwCZNn6LUmrmthr7JXUS4oIPW8Ayg==
X-Received: by 2002:a17:90b:3144:b0:1dc:c4c9:ce08 with SMTP id ip4-20020a17090b314400b001dcc4c9ce08mr19016436pjb.164.1652115109236;
        Mon, 09 May 2022 09:51:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a8d:b0:1dc:36cb:7c55 with SMTP id
 lp13-20020a17090b4a8d00b001dc36cb7c55ls13399pjb.2.canary-gmail; Mon, 09 May
 2022 09:51:48 -0700 (PDT)
X-Received: by 2002:a17:902:a60e:b0:15f:16f9:969a with SMTP id u14-20020a170902a60e00b0015f16f9969amr4026000plq.110.1652115108639;
        Mon, 09 May 2022 09:51:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652115108; cv=none;
        d=google.com; s=arc-20160816;
        b=wOhFdvHWe2Kkmg7z5OHzHypFrpQtnpAOXNssqL86eN44Iq3s6/C/Iwge/9rs8+l8zB
         Dxjc5sk3q6sPo42+Kbx9z6xBhWggZle+QI+YKYVZckIPNX+cChJ8VqzJjrNb9DrOn8E3
         P9wac6d6fSROfs9Qbt3PZ77qV8HX4ZxqtPTgcbG0SnwYAF9vcZXUNZZtvvQ/Bs9gXi4g
         zcCKq8/75Hvh6rm4Y+1+HDEE0wcDSv8KGtrJYhlvTgFce6M3677u75ilAiO1UHS88jwI
         BmUvjPDJIBUcqXbXBSC4gDWGEOlmK7j8/JXmmimfG3zuzLNHk4D4eCgSeFm/6hY4/S1E
         RU2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=AzvWHOfj+wpM2MrSAAiTWWdIGXiz9ownxOGyf3gL2bw=;
        b=nUxMfmhuofzxgquJM4RzbmqAzkgxXiveliW7uNvu4UFX28+KbIZ10GrS8nCwGVev5E
         fvVEWv5PAqcv/H7vvAUO0uMmQVkYc8E96d4YfEgUbEy0Wb17k+vcLt109l80qWrSjEsq
         a63f9vM6ri8rspgFUZcPrv0ZavvVtPOzzxmFZHB5A5nLdwebqCVkEGviJpe05jbsStq5
         uluKEcznmC+kG/rIcWgRGbJebPf0X8Zxd0gO6DEq+lv4tFfXBgY7pLMgGZhS5OSYYp1m
         zLSaFjuRacR80nKzyu/BPhfwcPscahU1sOA+I6TyU96hxH3tuoDEqOpe8Duqke/AGcKT
         W/nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=mPniJxZ6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id s19-20020a63dc13000000b003aaecd7def5si530831pgg.2.2022.05.09.09.51.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 May 2022 09:51:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id o190so15975835iof.10
        for <kasan-dev@googlegroups.com>; Mon, 09 May 2022 09:51:48 -0700 (PDT)
X-Received: by 2002:a6b:8b17:0:b0:657:c836:de6 with SMTP id
 n23-20020a6b8b17000000b00657c8360de6mr6954751iod.99.1652115108395; Mon, 09
 May 2022 09:51:48 -0700 (PDT)
MIME-Version: 1.0
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 9 May 2022 18:51:37 +0200
Message-ID: <CA+fCnZcPuVLinRupbjm679b5yPpkqvMrG52jK9rdZY32qJCsvw@mail.gmail.com>
Subject: Is ARCH_DISABLE_KASAN_INLINE needed?
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=mPniJxZ6;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b
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

Hi Daniel,

I noticed that the ARCH_DISABLE_KASAN_INLINE option you've added in
158f25522ca8c ("kasan: allow an architecture to disable inline
instrumentation") is not selected anywhere. Do we need to select it in
arch/powerpc/ or is this option not actually needed?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcPuVLinRupbjm679b5yPpkqvMrG52jK9rdZY32qJCsvw%40mail.gmail.com.
