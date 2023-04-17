Return-Path: <kasan-dev+bncBCCMH5WKTMGRBS7V6SQQMGQE3TO326I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id AC0026E479D
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Apr 2023 14:25:48 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id y5-20020a05622a004500b003e3979be6absf17532187qtw.12
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Apr 2023 05:25:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681734347; cv=pass;
        d=google.com; s=arc-20160816;
        b=NOc7wxgNLKI6qKi+4zR5BrSmBWcxwk0Z6/ELMt5H8jtixQrLAhJF5lz2GXuyjbxnsY
         H2ooTOMo57eHfEy4EhxDrIQMqm039+9ahioi1xJ8hYv+rzdl4Fk8XsOQV8Iii6mwHQP4
         HZfNek92jx8CayhoOxkE/RhhTewCMbylWSTV/PKfszfnlgsEIC85XXjEdcuFFwm1r+A5
         3g1Vk+j74xhmItVXhnnOh0o6faq9/TT+Ux1CgOmc9mE65kjHlPsuJGL4sRsoHcWJdsC7
         2sVl/jHCX4qb5zuDYyxCYNd656vKD5p9ppUjLkwQMN28dK0z/le0FWuManB+5g9K/GAm
         yUIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=APRLMIo4vf5d++Agv+FrYt4mzNCziWrxZyYQ0WXzn7U=;
        b=YkwzN538nkMcXLlSD6Wmw3rw2BnBYrwYba7khmIpZflqXIkbjE0ehKGiKuZjH7XduD
         s0vPvqQBj+xNv4IjvYwYy3Cqk7vQg5/KHjzvIPeiVPcUEe+axtP7+q6rhgUVs1/5/R0B
         NTdBdMUln3xSn+E0KXskjXgQzFZBYUJjsBdxGKxOQXNPdfQ5uZCn9rscUdSEw/RoiS0M
         C04pRiU6waCANpmGBNurt5CxN5tVKKGeYbmENQXHubRrXe9j8NBsNfz9JGTmXRwxxkld
         32TziZeNRnchghYL19t2E+c7yKvPfobPAIT+aBPKecKGyZMNBmJAhyeIo2KqFXyIttfT
         o2Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4IYfU7fw;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681734347; x=1684326347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=APRLMIo4vf5d++Agv+FrYt4mzNCziWrxZyYQ0WXzn7U=;
        b=oDbivqP+3T3PKZ6TwZNj59vvdysMmaGcCnoRcI3VRFwfdE1Z4iNNHWPvPvezR7zJbG
         l78WXl8tK2kBF1WgAaV13OZRa2j9shshwl0eHB1xo1PpT+czLIXQvNxRWMbvEGtNpPM+
         fr6TFULiQPGqbDwYh13sTwK56P1WqPYPfFeIdiHdmGPxMhBPzr4bnV5t85Hox3qSBeY0
         vEUPDZdjjEaNfAiQev+GUOHPWFNkxn5OU+TOa3eA3pz6tc8w+X2NzDQzhHtmJsGIUJ0v
         q5urhFPgMMWtlCepsafVaDgyk765YEwycTwUNwZEH9nZ2H6nIg2YZN747Y4wZ0MUGsJ3
         AhSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681734347; x=1684326347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=APRLMIo4vf5d++Agv+FrYt4mzNCziWrxZyYQ0WXzn7U=;
        b=YryXDFEa0IiHdjm7S15NIrvM1fNd4d2ktr5mqhC36u76QN+WACnsgxlztE0O3OoDni
         Xw4oNEerWMYWTZv6ZBz9lpTAmY1HQ0+kGLauSEKU++qFYS9eG3MCNpfu2hHdkZLTyMbp
         oRKgPxlhr+dspGxogEILCrIvCweXXiL8WZ1sr1JdmwR427JV0l8J87SyfiGzy6F37vCI
         C2n0UyDSGPD2ten41lbs0fEyuhkUDb63bbHztKptq6nR/3ig0hqGxKS+Qro272NL8nk5
         jF5guMdGiB4/693yw4f6yM0BN1O0ysRNjyG1chZnMdVdoU2DFSPp5QgueSkOR9MRGndj
         9DFA==
X-Gm-Message-State: AAQBX9csAGLOvjhP+rXMokyVna3ZlyIeNif3+G52dZrn8AZdnF2Q7iA3
	piucho3UNxn9B4LUJy4xSEI=
X-Google-Smtp-Source: AKy350b9zlDf/hiEbXhsDSHQkfIKWMWT8ukpozj9LwMRylj0Y5nRD/q5mbVl+mdYLKD3drypmVgqtg==
X-Received: by 2002:a05:622a:18a4:b0:3ef:3204:5158 with SMTP id v36-20020a05622a18a400b003ef32045158mr580111qtc.7.1681734347361;
        Mon, 17 Apr 2023 05:25:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1b10:b0:3ea:faa4:c987 with SMTP id
 bb16-20020a05622a1b1000b003eafaa4c987ls4214529qtb.7.-pod-prod-gmail; Mon, 17
 Apr 2023 05:25:46 -0700 (PDT)
X-Received: by 2002:a05:622a:1302:b0:3e3:91da:488e with SMTP id v2-20020a05622a130200b003e391da488emr20930883qtk.53.1681734346816;
        Mon, 17 Apr 2023 05:25:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681734346; cv=none;
        d=google.com; s=arc-20160816;
        b=y0Eltrba4RJisUzcGHAoWs9rXjNrXWDFkQqw+rtKzEsCMAuS0ivFOxuX6cvsTLSnxg
         a8yzQdoLjn0NgTILtmf2GnogMPCMGlXBvk4TSKrOYErYrlYYZShJ2pDoPwZpvmnxZ+EM
         b5uuP1S/eLPns07dEA9MRXbXi1cAg9wXSLejReHOzOVitvHt+tSjsCmqBmV4vPsQd/wd
         906srbgXD7yAuDNSmTKX08tAd79bG/FauGkpcZPyDYbRaPvKuXIoIzTHDjge7ZtitNnj
         EClyEqOxy4qWlHjSVk5R72mplQmKFHRu5ObWxqOX3vzLeNxMVrZCILi9GjK/Sti2PkK4
         lhTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JixgYwWa7BlwqObsT/AUW3SuD9EHVR6lIpoIyDwEkmE=;
        b=mquaXdv3izmBTHLiN/zcM0csL/YYRJmgnohyr6n4nzDdnFJFw3DbbM85DpCw7kth27
         m/xK61HBTvvdrVTZEiOHnWDaSOGL5QtQu4eI+wTOyzJM5SuV8bhSIijL+3YH6QOYwsmz
         P/fvA0XZDWpmzRgRhZuyFPGtUISz+BqnHmNBzEaM4g4mkiTbPzIOCePZcfHIDrKmxx4A
         FnZMalB8KypOO8ut1sBt0Nv8CEFXPZO9TAylC9+xve+B4GznpMlJqlYixOcA9T6AzdlD
         /ev5Kzu6N1SznF1T9mB0M5HZ5wLfMYOoekazFAUfBgqIDLT9i/4p+O09WJNhZ5whdb8G
         ecSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4IYfU7fw;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x929.google.com (mail-ua1-x929.google.com. [2607:f8b0:4864:20::929])
        by gmr-mx.google.com with ESMTPS id ci17-20020a05622a261100b003ed73a9d023si271093qtb.1.2023.04.17.05.25.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Apr 2023 05:25:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::929 as permitted sender) client-ip=2607:f8b0:4864:20::929;
Received: by mail-ua1-x929.google.com with SMTP id a19so2164095uan.1
        for <kasan-dev@googlegroups.com>; Mon, 17 Apr 2023 05:25:46 -0700 (PDT)
X-Received: by 2002:a1f:c682:0:b0:440:4938:fe24 with SMTP id
 w124-20020a1fc682000000b004404938fe24mr4010877vkf.13.1681734346378; Mon, 17
 Apr 2023 05:25:46 -0700 (PDT)
MIME-Version: 1.0
References: <20230413100859.1492323-1-quic_pkondeti@quicinc.com> <20230415065808.GI25053@google.com>
In-Reply-To: <20230415065808.GI25053@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Apr 2023 14:25:10 +0200
Message-ID: <CAG_fn=VEdPHopbJgip97uD48sW6OX7MOh4L671dTxuc_rG1gRw@mail.gmail.com>
Subject: Re: [PATCH] printk: Export console trace point for kcsan/kasan/kfence/kmsan
To: Sergey Senozhatsky <senozhatsky@chromium.org>
Cc: Pavankumar Kondeti <quic_pkondeti@quicinc.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, John Ogness <john.ogness@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=4IYfU7fw;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::929 as
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

On Sat, Apr 15, 2023 at 8:58=E2=80=AFAM Sergey Senozhatsky
<senozhatsky@chromium.org> wrote:
>
> On (23/04/13 15:38), Pavankumar Kondeti wrote:
> > The console tracepoint is used by kcsan/kasan/kfence/kmsan test
> > modules. Since this tracepoint is not exported, these modules iterate
> > over all available tracepoints to find the console trace point.
> > Export the trace point so that it can be directly used.
> >
> > Signed-off-by: Pavankumar Kondeti <quic_pkondeti@quicinc.com>
>
> Reviewed-by: Sergey Senozhatsky <senozhatsky@chromium.org> # printk
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVEdPHopbJgip97uD48sW6OX7MOh4L671dTxuc_rG1gRw%40mail.gmai=
l.com.
