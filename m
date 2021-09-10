Return-Path: <kasan-dev+bncBDGIV3UHVAGBBTGN5WEQMGQEYVZS4ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C014406D50
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 16:08:13 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id r125-20020a1c2b830000b0290197a4be97b7sf674572wmr.9
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 07:08:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631282892; cv=pass;
        d=google.com; s=arc-20160816;
        b=az0OA5tWacB5TWMFrzCJMow2uQb26wsZK+7f+WvpxzQQcRH1eB8lAfhAMy37gPZBIG
         1NLsQBuJO9QD41P+iEf93BtOF/8KnBLtrVDUaUxC/JxPoo7FVBnu8laPchkYp4O8KBLv
         /YgHl4X4H0LJ9lNMW+hypFwaBsrqno/KP0gZwvC6yXzitESy0jK9ITtiX1ESoW5c+sCK
         WhFFnqfvc98tU/CTIO4LnRfp0uqrXEnXw/2B22nw3QKI+gzuxIT9IK/frf+/RBS6JTn+
         H53XzRMIhYVWXARsg+V09X/8b3rh4n9uHX26kkskmIGFXQdgzW0qzAPE3N390C3t1pDX
         GlCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=M8JIp/m+irlC5uhOgGqy1EMBs8PwORz2wy02m9xh33Y=;
        b=krMCoU/kD8CPU7rEyxaHS0gNiLbljZa6yBwSViMzD7Q1FTTkKJo2aMn6cIEeFJPh23
         5suKFgQQx3AEJc2WKv6TBOlIMrIt1jXJTg4oNZAfIQYuTqzoOM8m13wGBrTTNdOQB0vs
         1QWFDLTbpB55ZRFMRfJtkLhS+UjxGFnOdVlAdKG3/tRs3Z0a73NsXCmfI8zU9Bm4Z4W6
         0Htu7PyeBPRp+ixl+flK9XNRBIhTkgpZ88vbnRQOKCwHysHq8eq0kmq9Tu4+EPPj+oWp
         XlGpCmmX31RQFQQZYo77lOe2SBnUa/PQHOt41ZOMhGqWP2c8qMIzecN3rTxoKayI0QE2
         Nbpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=tIMCArcK;
       dkim=neutral (no key) header.i=@linutronix.de header.b=7JsiFf4a;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M8JIp/m+irlC5uhOgGqy1EMBs8PwORz2wy02m9xh33Y=;
        b=FS93umpoYZGE6xE5EUNG5dbf/CriVu653j+5kc7ugRaKdb9dKPvZt1/ss16oik9znk
         jHgJTcEGy7qT75ZEKmGVyfaRDG5sYYx3BdFOISrUIDY5uUgzyK2Ky6JmqfqUsrXPGERI
         yKlx29Oc800CS+sRUYvOejBxS5EZWnE/AAX/fKWFfYXwMN6QvrrJC9Hz6URVBOM+Q5es
         ekQFOSa1HuHzaS1bXYsuiqwEbgj1z//Ymit9GeoGP5MVu6RRk3+ElkAhiRfvJAoNz6im
         0mSkjJj9jsAbVmpdeMpAWCIwy0Cq9GvufyXXz7MND581yr8Epud4mpxvXV8n5HYQFDus
         6E6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=M8JIp/m+irlC5uhOgGqy1EMBs8PwORz2wy02m9xh33Y=;
        b=Jv8kkNHsf7Vjng6Fz1vbGlQ20Z5z1JKFRSEufgVqUot7P1nmuw+FqeondXRixG7w4b
         LcuPlzzEr88Ge7wHnWbJc8Z7vtOoNLmcfBqbC7dIvmunagzlnnu0jQF9yITYd6wO4RfG
         wz3qnaMWGx/6JhjGEWzG1fdz/ycxhLbPY2jbhW2uw5KK5Wp7xuE8xZ4WUNVemRzniz5W
         s9Xj84MJRLM9V/kApTKXIvzyneyFR1txhw9IVcr5jD+VRJYbI8cx5grJxIWdf51BJ8XF
         5dYtVH5MlSPa0bH9f/n8cILVFMnB+O1dbPhMsPMTNmPS1md3WC+Lqs99HWFJLu0EOMSw
         f8ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531O/sfa+9UUURoD7LDzenXWgGIBZn31du9UGOYl+pTSHv2X8S/U
	Hs0QJCNgob7svD57EYmB8fU=
X-Google-Smtp-Source: ABdhPJxJMrMeHD5W0jdYNunZ0QPiG10+iH466IffRc4hbhsHmtHbRD5U9opE4TfOWvbBzaPZhZr1JA==
X-Received: by 2002:a5d:4803:: with SMTP id l3mr10087596wrq.61.1631282892789;
        Fri, 10 Sep 2021 07:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a314:: with SMTP id c20ls7462739wrb.2.gmail; Fri, 10 Sep
 2021 07:08:11 -0700 (PDT)
X-Received: by 2002:adf:cd0f:: with SMTP id w15mr10030052wrm.346.1631282891940;
        Fri, 10 Sep 2021 07:08:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631282891; cv=none;
        d=google.com; s=arc-20160816;
        b=vS5LOL7etX1rperYxF++MOeduJ6z9ACnhSuFk/51ygxyBlim85sYPs9sXdLQwmlzEb
         YgPzI44y7e9qc0RHfSDFGtedsi39qba12pEslpK5liWvSSRkixO1E9uUevmCm2Tc0c3s
         QVOKgToGCt8qTdGVWgRjoLHuKhOhfvDn5D26jsBrhwb8uCrafdI8Om5D5Qxu1Dbc8hTk
         dUX2hk6J0ESJ3bm7nE6CHL7XEmri23fYdfD6rpfB0e3gUGT+OB3f8+WOmvRqI7D3lMC+
         81It7EnxlBpUcB8O1JFOV93LQs2mAnHKKaDQyLfthJ5t4uTleE7zRCpuRLE0rq6mfGTG
         8uFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=bSyyP9yahgxFA1b8RnoWYThoroPSM6gbfo1YmaotaKo=;
        b=LHdUQyTtqwCfOlDJ9lh0SCCU9tjTw9juiotsGkdIaGZ4Z/PVKGxpYdUYpEmP/K/XfN
         jjChkneekoEeV00YR3XydfRJoCkTbNxr6BXiDiLIE99KlMYYRJgMyNLX27EwQ2rEQI3T
         I5wOis+HfSiFJygtXx3nrASOM7fJLKVpOVOI7uzxHj+XwzQsSEpvO7OfA0NOhi6GMAXn
         MLeCLu6t7dnSWhO+ysziEDuO0iDNMv+G9oc60E3K8+8BzziwbxMws3trk/UeW4UEmPk1
         zq07oLgMcZZSq6wvX/Zd+m0BZNcORh31fvGzro8m6XC/Bq4wYHlKO9xei24KvZ6Nro8K
         pCgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=tIMCArcK;
       dkim=neutral (no key) header.i=@linutronix.de header.b=7JsiFf4a;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id c4si412409wmq.0.2021.09.10.07.08.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Sep 2021 07:08:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 10 Sep 2021 16:08:10 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Shuah Khan <skhan@linuxfoundation.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vijayanand Jitta <vjitta@codeaurora.org>,
	Vinayak Menon <vinmenon@codeaurora.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Aleksandr Nogikh <nogikh@google.com>,
	Taras Madan <tarasmadan@google.com>
Subject: Re: [PATCH 3/6] lib/stackdepot: introduce __stack_depot_save()
Message-ID: <20210910140810.jxb6sfgkdzefqgio@linutronix.de>
References: <20210907141307.1437816-1-elver@google.com>
 <20210907141307.1437816-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210907141307.1437816-4-elver@google.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=tIMCArcK;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=7JsiFf4a;       spf=pass
 (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2021-09-07 16:13:04 [+0200], Marco Elver wrote:
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index c80a9f734253..cab6cf117290 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -339,6 +350,25 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>  fast_exit:
>  	return retval;
>  }
> +EXPORT_SYMBOL_GPL(__stack_depot_save);
> +
> +/**
> + * stack_depot_save - Save a stack trace from an array
> + *
> + * @entries:		Pointer to storage array
> + * @nr_entries:		Size of the storage array
> + * @alloc_flags:	Allocation gfp flags
> + *
> + * Context: Contexts where allocations via alloc_pages() are allowed.

Could we add here something like (see __stack_depot_save() for details)
since it has more verbose.

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910140810.jxb6sfgkdzefqgio%40linutronix.de.
