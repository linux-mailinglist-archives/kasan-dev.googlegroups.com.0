Return-Path: <kasan-dev+bncBDW2JDUY5AORB5VR5ONAMGQEHDCOYLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C97F4610157
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 21:16:07 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id z15-20020a5e860f000000b006c09237cc06sf1885913ioj.21
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 12:16:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666898166; cv=pass;
        d=google.com; s=arc-20160816;
        b=XkLUZl+RYuvd5ci9q3x+jEGr+nUUExt2oXkT1l1BA6DWyG8izbBP+xUCLux0VityX5
         gnGzxm7Gq52k4/mqX1LJv87sQuurH/NNy0VYy7wYxVHeVD7B8vflAM30aUoogL+9d89q
         iILUT2hqHg+qTZc+whIkdJJXSqHk0oUUwD4RDKvxRR/xEfNgCjMFQGLHacG5uFNRQVRb
         9m2gQzpQgA8TTgREdJ+4UJOc/TfXqQQFmha+lgMdDRA+kVghSS5JudtYOvR+fcRQQZYR
         NdK5xw6nit7KkkV788bNPzPa+mdDJxPwh7+3dA14M5SVynR1AqkULiHnTbtYYgdV9dwO
         3+wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Y2YfZ5NejYOj9sgMTSHBKf1vIshLtd6P53S7Qz1cOnM=;
        b=odWGyp/1oM/4Oa+GXWXPU1fUrNUGif+ydbdH1UQ1+h78q5Y2Y8t4VOOzFfqO7wMfbn
         UENIadJT5WRtJwIn+LbRv4voV2AJRf6Gv7cTblEeCYCgD5ElS1QriRxlOVAHa27RTQsG
         hVoqHxrMKbtr2bWwhmDxcqYHnmbvjinlAjdm733+FR1dheFRcpzht6LoVfiWfOptd+aQ
         j1XyiowlC58z3lIQ1sNob8pYw2aa67GyXp8Ip7a8BnfyY22DPGmylLc+S2pwD/6ev/GD
         0pxIuIOVdmDrKL80q4kbVs7SH/bZWgzQlDekNXekRBdqUGYzFtNvycqiuK5NEt3Orxrq
         CyEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=R0iWBH+H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y2YfZ5NejYOj9sgMTSHBKf1vIshLtd6P53S7Qz1cOnM=;
        b=cHwp3GeEEwHCcTYDF0209JjblfTxJPTXerLCn6ULs927hqoGaQ4g7kd2SzCPsOLNby
         IZhllOqu8sLMJxzXoc0QCYNFgjsihM6vlsVub0DcBrWkzjFzYfvr5W/R+T0750zoQwtg
         PZ5FRhuxyMTa6nij4q5vFfBGNuvK3c76/cPdg0RmPbjV8vq6Orz6JKhItGW7VU9thapO
         ONsBfhDOJ9JK4dXokQvDxeTQw63FpP6+lDKeNn7kKNV7WBgRzm1h8TSfYFgAE6gk+nqe
         gwUn7OtRJvVC/4CS/ZWecBqoBUwNbC67UdLJfc0uop6yVBC2jFhEaLzyAMNyaGVa3+nF
         4sTw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=Y2YfZ5NejYOj9sgMTSHBKf1vIshLtd6P53S7Qz1cOnM=;
        b=GNCzUgkdwlZAhZ+IYrAa/tpzRwwW+UWRzDjZjiB8DG366Vxccx7+YZX63wS0e4oI+x
         OlTAnaxQ7WcNFWo2HZgULWlAXE/mpuPwlxK1g+ufN8wQunQV8byxc2FNR0yeFF8ySr1C
         cq6wPomxSgTXbqsZefDMFjBKqGWjqEp/XFwRUxqxsLdK7AIIZghLERxOvj8NgtCoiZ/J
         aQQhBCqEzeX8LPM4W3mQIkWBFFHPYo6hqwe8KqLB/Wie9kc9/osQtV4shqhdW96iBCwW
         eOrnySw/EK2kTfIjPDQT7MB1fUzSdeZUQL8fekuf46pIRkeOd+b5oXBrbHNg8GLbsu+S
         7ghA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y2YfZ5NejYOj9sgMTSHBKf1vIshLtd6P53S7Qz1cOnM=;
        b=ZsdLNz0QV8rs8AURQs4Rekve8Z2C6wmc+ymaFzJejxftJzA2zNhg9miWNSUXY1qdmw
         U45nREP5grjqa89PmGDMdF4KY53sqkEQqXcEih+sFXwZ0yV5PL35P84QsEeXfDAQOLc/
         Ax4C6JGhYp75Vypr3ZucpBERZAt9VSV25li7O9CmZg1Jk+/NWVzxnC4+q30vLxwPukB+
         ObgAsS4XNK5lm0b+fbeGNncu+2Ex7vXI0g6kVd9TRPtCCl9w6YNphMvFWvb5AAfw8ZhD
         /lk62IysA4zby3BNp2g1a19tEFgJTd1LL41/h4kAHZ1lDB8FuBePtdvIQ3FmWw8XPiSN
         Bp6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0Bw5iTlzhd10GVqrqaQ0lXCNe9FKPKYpgJ1v32O1QBVFAjCa30
	JVCJBbAeGsx0ViUj/omcLjE=
X-Google-Smtp-Source: AMsMyM4PFKZIE9wekXdO8oKxvYM8GS2MqrUwshLHkya00olJomYlGsmhAeQW7IYsp4ZpepnFZtcKxg==
X-Received: by 2002:a05:6e02:1287:b0:2ff:dd33:8483 with SMTP id y7-20020a056e02128700b002ffdd338483mr13249002ilq.21.1666898166265;
        Thu, 27 Oct 2022 12:16:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:10cf:b0:2ff:7d6b:f9a with SMTP id
 s15-20020a056e0210cf00b002ff7d6b0f9als32482ilj.5.-pod-prod-gmail; Thu, 27 Oct
 2022 12:16:05 -0700 (PDT)
X-Received: by 2002:a05:6e02:1885:b0:2fa:1ae2:2902 with SMTP id o5-20020a056e02188500b002fa1ae22902mr28817578ilu.283.1666898165872;
        Thu, 27 Oct 2022 12:16:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666898165; cv=none;
        d=google.com; s=arc-20160816;
        b=WWCMT6rtB5LbDHjBx0AEmhtxckeMBRp5dT19yc78Nqp6MYharO+8ziDuXHi05Zzbnv
         5Md1xeEwAH7/J3HxQ/5gUGKE9eNSM403Vo8hsdHNHbWfhc73iOPinVGqw/innCYUwvyi
         f0z+//kBVwnjfRAAy9fVCEs3cQm7s6szidO7/NPi+AMmgdYz2NPiG5NeRXEbNyxqgZym
         xUajR5QmAnqbEPDq2A9ej+4KDJDECecYiJ2PNZzHNznMP2Oxw/wI2w+KC9+BrffvC0Zw
         n4PX0+UP6a7H47JQPYMtRd7ilNf15gtC0E5ZElTeR9eZosgI1wjJJGgGX+pm5a6Otydw
         eAWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eCsVCuaf2go92u0eYyN6AvJOsvbg6jhQcYiOWielii4=;
        b=PBVpoMh/kwykW18ri0pPDYtMIsVeiSJ/wJlJZx+K07uCISg64Nc1WlRCXygltRIMDm
         uw+poOlti+uU9m05NCADm83fUuV7xOGMMaQCQ23+NlsqVdo/kuEE1kvkS+fEc7PstEUX
         qnA30aBpwwMPSCeoIEQ1VEKTGphtTJoqpi8sy5U7TyQCpSqp1E/Je2Z84Jpwj7dF+aWt
         HAyw2Zq+rHew2uZO+CSDnZ/Hxg2SdBw1bA3GkCYCXcA2wNaBSr6RDibfMlBvehoU2MAK
         jO4wgywNXdQIUh+tDEdvJ3EGrgxmfcshkV2oCD6Y/2klIwVaxcDuFamaHrvN3FgPF+T9
         H3mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=R0iWBH+H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oa1-x2d.google.com (mail-oa1-x2d.google.com. [2001:4860:4864:20::2d])
        by gmr-mx.google.com with ESMTPS id o18-20020a92d392000000b002f9b3c58452si110949ilo.2.2022.10.27.12.16.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Oct 2022 12:16:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2d as permitted sender) client-ip=2001:4860:4864:20::2d;
Received: by mail-oa1-x2d.google.com with SMTP id 586e51a60fabf-13be3ef361dso3449749fac.12
        for <kasan-dev@googlegroups.com>; Thu, 27 Oct 2022 12:16:05 -0700 (PDT)
X-Received: by 2002:a05:6870:c182:b0:12a:e54e:c6e8 with SMTP id
 h2-20020a056870c18200b0012ae54ec6e8mr6423090oad.207.1666898165661; Thu, 27
 Oct 2022 12:16:05 -0700 (PDT)
MIME-Version: 1.0
References: <20221022180455.never.023-kees@kernel.org> <CA+fCnZcj_Hq1NQv1L2U7+A8quqj+4kA=8A7LwOWz5eYNQFra+A@mail.gmail.com>
 <202210271212.EB69EF1@keescook>
In-Reply-To: <202210271212.EB69EF1@keescook>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 27 Oct 2022 21:15:54 +0200
Message-ID: <CA+fCnZeTO_eQjSqysoToKCqUhsXc8jL93TdE8W9Fh+xrbUiFtg@mail.gmail.com>
Subject: Re: [PATCH] mm: Make ksize() a reporting-only function
To: Kees Cook <keescook@chromium.org>
Cc: Christoph Lameter <cl@linux.com>, Dmitry Vyukov <dvyukov@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	Paolo Abeni <pabeni@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	netdev@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=R0iWBH+H;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2d
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

On Thu, Oct 27, 2022 at 9:13 PM Kees Cook <keescook@chromium.org> wrote:
>
> On Thu, Oct 27, 2022 at 09:05:45PM +0200, Andrey Konovalov wrote:
> > On Sat, Oct 22, 2022 at 8:08 PM Kees Cook <keescook@chromium.org> wrote:
> > [...]
> > > -/* Check that ksize() makes the whole object accessible. */
> > > +/* Check that ksize() does NOT unpoison whole object. */
> > >  static void ksize_unpoisons_memory(struct kunit *test)
> > >  {
> > >         char *ptr;
> > > @@ -791,15 +791,17 @@ static void ksize_unpoisons_memory(struct kunit *test)
> > >
> > >         ptr = kmalloc(size, GFP_KERNEL);
> > >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > > +
> > >         real_size = ksize(ptr);
> > > +       KUNIT_EXPECT_GT(test, real_size, size);
> > >
> > >         OPTIMIZER_HIDE_VAR(ptr);
> > >
> > >         /* This access shouldn't trigger a KASAN report. */
> > > -       ptr[size] = 'x';
> > > +       ptr[size - 1] = 'x';
> > >
> > >         /* This one must. */
> > > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
> > > +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
> >
> > How about also accessing ptr[size] here? It would allow for a more
> > precise checking of the in-object redzone.
>
> Sure! Probably both ptr[size] and ptr[real_size -1], yes?

Yes, sounds good. Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeTO_eQjSqysoToKCqUhsXc8jL93TdE8W9Fh%2BxrbUiFtg%40mail.gmail.com.
