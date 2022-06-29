Return-Path: <kasan-dev+bncBCJ455VFUALBBVUL56KQMGQEXCT2UAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 21ACA55F405
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 05:24:08 +0200 (CEST)
Received: by mail-vs1-xe3f.google.com with SMTP id a21-20020a05610234d500b0034c6d03513dsf846471vst.1
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 20:24:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656473047; cv=pass;
        d=google.com; s=arc-20160816;
        b=dEGlbKOm6ewxXsGo8+bLY/vy/cJ6vO1XzDuohB73RhqCdbf5xekYI4EE1cGilYSows
         oTxQtNCisBnlC5Ud3KPG6GyPEbN4x4rFCtAWlwiUplyP32bx6LuMCHwyWQWieI7cvA/r
         604z2O8mzSn9xbupc4m79KIlGBv8yRzC9TA3dYtQdM9LjEKXNST47rN1HyQj0iv1tUDw
         pOikmeTl6Wdl/HMAHB/SS7LVVBb0BaB2V4mFG3mzx6wqYHLnrMzJbWzDqsUX7gyhwg6D
         83aua/sylors6B61EdcNSG9T2mtsIyARVw2UVbu7tqUDnlVQFw0uiqmxMPG6UpAyTa01
         jXPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=dIVAOELLmfPYXoqyPazkpAZCH8RjLNlQ4xLiVbldges=;
        b=dqzxQzhJUDPeFT6KWOZncFEuG/ciKl5+hFPxL1jxi2GmccRchXqp98uO/29LF3ieqA
         PQxgT7qraNgycURmpovWAsQWcHfY6sVy76oUeTW0WH6VGpPlcza3m8XGNIhNVvIQRs8p
         VGJqk1zw3nLVpPBJAdHiJSpewS/tEHxIw9CO3242JNJ2y5aqVVCVFmtlJXL77RGg5PX3
         /K99sP8SmhHL59tbmWyLtCpr7KK6Jii0TWX8CU7WVu3UQQzEYPJry1DzKofPPEaNoUxb
         lbL6QpJDqCUSBboek2Iu/bq5L1vKP8cOWLndblxaUZ7ALBdWgL9K7l1oHZ60d57WhlBH
         FjAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oFx79pTD;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dIVAOELLmfPYXoqyPazkpAZCH8RjLNlQ4xLiVbldges=;
        b=HmOEZsXa0rueNAX2F23RUfKpG1TJFU4WSQObC6vY0m+MxQQQvI0jgiawabb9zItlTK
         /8Ad+SMe+tRsDHpjhnJgXg6vA4CWak7aCtdERqMzcCjLcraADG4gJZtF1+1x3Vb7830h
         od+lbt4JsEyiJm1oTDiJ/nt43tBFCtzrVh9/+EBn1N1fG62snRX/v4H5gvvIiLzo2Mvg
         qOf9klAapItgGYbj00rPVS+aQty80ktNlic92uJ4T+D8fRhNzEm1JQx6qFyEFn2aETeQ
         S42QmscKJfEniqEusxR1dHgvtGWyvJjiaXN+Mxp9Onp4pQ8HVUFTeLRLN9Nsq9uojHWZ
         a4Qw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dIVAOELLmfPYXoqyPazkpAZCH8RjLNlQ4xLiVbldges=;
        b=c8slXdQXOM3A/Z2RL36+qx/RtRtuA2KU9k7rfb4/CJrsrHByNaTL7Z1XHfHeH31zES
         sf58oaS2BfD9ED6vdXzjx9jCb1bmn0SM8N4DgsHPCk/kVWK4UJt50VsAHrWMZJ1YC5qm
         1U+59OnKH4mjSooVT1EkjwyV7xvZbCN9/i2JKgSmK1divv1En3oSNVkfZV6TW/HUN5kq
         F8cfzFuxSvoKffF/IwmAlJPj/fvABGbVragP4hfvsqbkvx6EyNN4k9UoUzTVdxTUmo+j
         6tFmU7diG+y7zQuy2TTnZ1Ncr8LoGNf/WGhTTMVP9kxwkMYx5rDWAsrycOCtsz/ZJcLH
         Gcqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dIVAOELLmfPYXoqyPazkpAZCH8RjLNlQ4xLiVbldges=;
        b=l75FfdW5ucVf2Nt5Ww1DYZDqTNHH79Qqy5+uFprrzg2oTiLNrONIHdQYPkRj44cejM
         6XCySDboRjGqcMnmaexqhHMLiPzzlN9qwo0edZywYptXzeOJACQyddEHT7u3ut/+s8bA
         lMkJG5KQW3Df0hrVtK7nyOkWp8ry0Bex7lzto0zy7PVAxKsetrm2wP9Wurabyti7iGhI
         kVcmrTdBpU+YrwV+2VZ4uAx99AkfwdKdcQsH2x0QUIpsn3aa7P7hD/3aGmjMqMDtN1i1
         k4/j7ikyL9CDhLUD4m66QKQPZcasDLVw3iuwGvr7um5VjW/IF3qmjvbdliXsyqwoF5Ud
         01Gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+fduwTtVgVDYATRjLHPM9GpAB3xuavxGXLtGYqDLUGRn6V+CU9
	SBT2Pvsdwljvtv6APCwGAgI=
X-Google-Smtp-Source: AGRyM1tVWs89DTPehRbwmr6/IOjiXVhVuXBtnvHFnHtp67KGB75uJDkuJrPKhpf/4mHDjhCLs4nH6Q==
X-Received: by 2002:ac5:cb6f:0:b0:36c:424b:6d79 with SMTP id l15-20020ac5cb6f000000b0036c424b6d79mr3078319vkn.14.1656473046834;
        Tue, 28 Jun 2022 20:24:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:728c:0:b0:36c:3064:d5a4 with SMTP id n134-20020a1f728c000000b0036c3064d5a4ls2210539vkc.5.gmail;
 Tue, 28 Jun 2022 20:24:06 -0700 (PDT)
X-Received: by 2002:a05:6122:612:b0:36c:5776:1836 with SMTP id u18-20020a056122061200b0036c57761836mr3313486vkp.6.1656473046262;
        Tue, 28 Jun 2022 20:24:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656473046; cv=none;
        d=google.com; s=arc-20160816;
        b=LvVtspiJ68s9rfFoRt7a09kyWq7qFSqDKjb1kp/Jd6IbArVuQMA/vrIK0Oj4ouTbP8
         /Qm6fJXdz1jdr/7/IcMd0+AVAq4URoNXCy4ozvZgZ64BRwSWo3h3LD544yNiZSk8KR1J
         ouFR9e965+ZoKTdfJv7hyCtq1/zvpXW1QzR9RoNo8atAzn0DGGldswblBrPISIDZ9CDr
         KrgT6CD66/78j9MIJWNCGrunXPl+082yDkzGqKD2y0WtxYy4ZlU2T68pkjcIsYHg0aWp
         IAg7dxt2gtZrUpQi+vYu0hOdLJRc5+5DruXTqPvUzNih+HcMCaE+jWfOgPIfoCAPXABG
         XiRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Fj7BbdljqsoGparCST0EyCcPUKNtLNBlk+LCRCpdJLw=;
        b=qnattPmw6WpfFLKGiJpU5LgwOfEkLSmbdKEaM51JbPEVVoxTXj3AD59gnzakcSTkrk
         YS3FZcIloymdlmMEyL2lE8rN3mQjEbPq0zaCIRfNJRHHjArQjoeEAtkXO1OTsjM5q8Zt
         elCTSpsWXN5L9zSkzQ1ovUz4uxXQfKzNvUyfDes9wM6hPfL+/pEm6gwWYbZtNQQc/f77
         M3WWefwtOZ6+13PpmhSdbJrFZJf+g8WnWC6jB4k25svIHjtXKjuccJRJ57sJEJuX42pZ
         xB2aO68MdFd1k7D6Bq0PzKPdrrtekrdqxn1mH8s/ILL+oPquq3VHZcWX2+FQDR+jLwV4
         XjOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oFx79pTD;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id x136-20020a1f318e000000b0035df1d45071si533609vkx.1.2022.06.28.20.24.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 20:24:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id n16-20020a17090ade9000b001ed15b37424so14681845pjv.3
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 20:24:06 -0700 (PDT)
X-Received: by 2002:a17:902:a701:b0:16a:65b:f9f1 with SMTP id w1-20020a170902a70100b0016a065bf9f1mr8387462plq.73.1656473045455;
        Tue, 28 Jun 2022 20:24:05 -0700 (PDT)
Received: from debian.me (subs02-180-214-232-13.three.co.id. [180.214.232.13])
        by smtp.gmail.com with ESMTPSA id p9-20020a1709026b8900b0016372486febsm10011584plk.297.2022.06.28.20.24.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Jun 2022 20:24:04 -0700 (PDT)
Received: by debian.me (Postfix, from userid 1000)
	id E4C29103832; Wed, 29 Jun 2022 10:23:59 +0700 (WIB)
Date: Wed, 29 Jun 2022 10:23:58 +0700
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Mauro Carvalho Chehab <mchehab@kernel.org>
Cc: Linux Doc Mailing List <linux-doc@vger.kernel.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	linux-kernel@vger.kernel.org, Jonathan Corbet <corbet@lwn.net>,
	Christian =?utf-8?B?S8O2bmln?= <christian.koenig@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Grodzovsky <andrey.grodzovsky@amd.com>,
	Borislav Petkov <bp@alien8.de>,
	Chanwoo Choi <cw00.choi@samsung.com>,
	Daniel Vetter <daniel@ffwll.ch>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Airlie <airlied@linux.ie>, Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>, Felipe Balbi <balbi@kernel.org>,
	Heikki Krogerus <heikki.krogerus@linux.intel.com>,
	Ingo Molnar <mingo@redhat.com>, Jakub Kicinski <kuba@kernel.org>,
	Johannes Berg <johannes@sipsolutions.net>,
	Kyungmin Park <kyungmin.park@samsung.com>,
	Marco Elver <elver@google.com>,
	MyungJoo Ham <myungjoo.ham@samsung.com>,
	Paolo Abeni <pabeni@redhat.com>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Thomas Gleixner <tglx@linutronix.de>, amd-gfx@lists.freedesktop.org,
	dri-devel@lists.freedesktop.org, kasan-dev@googlegroups.com,
	linaro-mm-sig@lists.linaro.org, linux-cachefs@redhat.com,
	linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mm@kvack.org, linux-pm@vger.kernel.org,
	linux-sgx@vger.kernel.org, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, netdev@vger.kernel.org,
	x86@kernel.org
Subject: Re: [PATCH 00/22] Fix kernel-doc warnings at linux-next
Message-ID: <YrvFzoH61feRFoxV@debian.me>
References: <cover.1656409369.git.mchehab@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1656409369.git.mchehab@kernel.org>
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=oFx79pTD;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
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

On Tue, Jun 28, 2022 at 10:46:04AM +0100, Mauro Carvalho Chehab wrote:
> As we're currently discussing about making kernel-doc issues fatal when
> CONFIG_WERROR is enable, let's fix all 60 kernel-doc warnings 
> inside linux-next:
> 

To be fair, besides triggering error on kernel-doc warnings, Sphinx
warnings should also be errors on CONFIG_WERROR.

-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YrvFzoH61feRFoxV%40debian.me.
