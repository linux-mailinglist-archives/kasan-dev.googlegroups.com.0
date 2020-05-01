Return-Path: <kasan-dev+bncBCA2BG6MWAHBBHEOWL2QKGQEBEQAVSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 61B4B1C1E70
	for <lists+kasan-dev@lfdr.de>; Fri,  1 May 2020 22:31:25 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id r5sf6080883ilq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 May 2020 13:31:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588365084; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yy/4kdoJZ6KfNH3wseQUHfBNJBlJQxIl8Gj4ZapTUCsksMLW8Bhk2Rec4UjLuv6DCj
         cJ4GHwHytRLr1pYIuuzqVTWhVeVcYfC2b4pKdOS+x8uk9HuwazyEnB/JcjxoJgY05vDn
         cph8LtI4bhxOBfGbq4W0HoCBENx2rj952l2TNJWtt/zMQrgVJh/6biPnmokA2GyurovV
         Oh1yjFPGbQQej3Y51UuZYoMht/+TxgrsBn94Fps2YypJeiGbXm0Z5qgN9NChYXwUPZLw
         tXhtz4AfetyiJxr3IYXN+Ml/Oycct3PiOxdSJ+n5tktnoTSAvYNHg4c/1ppd3hsXk/WS
         qhew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f5RKMn2QHs4dITaTZUGHkjuZw29byXXfvW4OkK5Kk7Q=;
        b=c6fARwq1bFPqNTHyVouuVWOpVYCECvmKraHqlXw/12Bf4fqqZZvd2Xf7xNFKwsxIm/
         7ITj7IFEj+as8C8/5MuJSw2twPeSHEGIt2xcYQDdlDO7/2ofc15GFVv0OBJwqBVWVV3w
         PLq8tZhNgmN0LGqtay5f5oAo+XNeeBWJbNrwJvyjWVF1eqrMI1nJLAY0AfC6JC5XNVJ7
         gIROozvSfzPve8ut+JqF49yGfFv6nuqqpAKE/gnHFTBRgN1NLdw0KCd+WY/K+YUpwTaf
         ZTQ5sE9vjTJhyBG1LNGb+ovh3WY226HHclRhBLHBscc02TO8hvoxrHNJ2aGyc2IW/yxC
         2hOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zc3KuQRu;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f5RKMn2QHs4dITaTZUGHkjuZw29byXXfvW4OkK5Kk7Q=;
        b=fR0hSbSEEJgnvKnk3KAxXMH4/ROFyoqejEo4zu7PzAirW3jtyg6w3kL8nYLuQ3+P8r
         FoJXVpdkZdtGeOw1QkYvyk8EtuZlKfGsS9f7LqpKhMBwBCE3Jg7yFYensa44JBOzgNLD
         LRFmkvsauOMQjFVyeAxE0HIMlpwNztr1aCzXvYq9ExYbtn7JfvtHK92GEDILQiqYm9Hr
         oGU0KhT7fiWX7NUchidnmPPti3Uif8QGZechgi/JrtR3j71LatQz6LOB0TuUpIEwv+1I
         RSroDOarizWC9RDxWW1lqcmzoA4MvXou7KlGjP6lrlmBJOkCoxgwlQjauBso0tEqB/To
         W23Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f5RKMn2QHs4dITaTZUGHkjuZw29byXXfvW4OkK5Kk7Q=;
        b=Bls6SfJLaIzXUMQCqHU9uqUCOJt5m5WTDy41fJNbxUZOdFeqoS+njAdSYgfi4WG7jY
         SPg4YniPSkLBoLmONkeIlNjRlpFWvXHwvsfl7fTAWhirNmD6kfAtcdhN7GuzIuZC3qvC
         G0eUzB8eUJ/bgxIauQaCchKY91Gi/5wv2ACiEIq+7f9l6DTT5xrQZ2DPeQTXTu2nd0B6
         2qAoGD+MEkRG9y5NVJw4mRaIX3wrtqVI2sgzrY8hSqTsRvZTO4nEeIYPngAvWT+BIY14
         BTKz0e6rgolu1M0HavBrfJWdldlZcX3yFBvj5C436W4T2cxukXrtBrFQAefPdGEGfuLG
         NLpQ==
X-Gm-Message-State: AGi0PubqdQVFV9hcxFaeq5q64D5WNcuHqqId8AMcBc7csQrngWW0gehX
	erD7h6iAmZqskfD1aS+ka2g=
X-Google-Smtp-Source: APiQypJuHTHHFYODtc58S0tIDf5ywhgzjRtK6TcCdhORYLC74iXSXLFq3PMr4Y91UqjdV31TWYaQTw==
X-Received: by 2002:a92:d846:: with SMTP id h6mr5229753ilq.248.1588365084144;
        Fri, 01 May 2020 13:31:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:13c7:: with SMTP id 190ls216365jaz.9.gmail; Fri, 01 May
 2020 13:31:23 -0700 (PDT)
X-Received: by 2002:a02:a592:: with SMTP id b18mr4949716jam.127.1588365083793;
        Fri, 01 May 2020 13:31:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588365083; cv=none;
        d=google.com; s=arc-20160816;
        b=lqp6PkSeuWwI2NtPHiAmBucFgd+Ne/rIPnEzAxoaPjyC8ICcjKUB/5ZdnssNKw6Bpy
         mT9ClThbi9WQr7h2nu1Oqh/IB6Ww7TcHc/E0EbpXvwR1U0nU93tSDSC6aE0fhq3RwFbd
         V4eLqX5PWSPt/VQ3za3kviY7gRaN4mDay3X8KDxnOmr6zITj7YoPEsvy4+IUBJWq23DR
         TUY2q2S2TTd7eC6hplwB8KmkYuum65zAbo8b/GaBihkHSNfyF/vlZtYHNNy7komQ65wk
         CSypiC1OIgHvZ+a14fmdG4F9FzE9FDDb0DtdQNJaWJL0NzbuubQdrwCD9Qo1xs9/Xb6a
         eb2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DVZsHO3B+82ZVvSvwD+6L84uL6YCwy6wqP9DD2caeKY=;
        b=FxYyT6RvgtnBxX+MkWqKluOLSHgkvPWTMqnxovJt54zl4Qla6C3BPVPxcsqB2n8C2+
         0I9nwPr6xjimXs3AlB6zyU0M+mtKROjH3/1VXYs7FpEp9qZuWgN/50TvEKQPWq8fT9WO
         2NWT0p2PZjjjnvFMnRulYl5cFrcsOQIsfdfMmA9pj+cOQh0FOVgKtSguRrycGZxxYTjq
         7aAPe5lcZsn+ZuIbyVt2vIQWRx8dYzJ0Tvkt1iC9uLprG3rrCOkWDEvBM5rVpHRDbSU+
         pJ0p8YpCCM+tVrmEN4ROFTZ2L6MjtdOV3IcqwVHxQ/rjC1iNhrMEd2JYmb8EY4xyoTf3
         /xQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zc3KuQRu;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id h14si340222iol.1.2020.05.01.13.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 May 2020 13:31:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id u22so4007331plq.12
        for <kasan-dev@googlegroups.com>; Fri, 01 May 2020 13:31:23 -0700 (PDT)
X-Received: by 2002:a17:902:a40e:: with SMTP id p14mr5817749plq.297.1588365082975;
 Fri, 01 May 2020 13:31:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200501083510.1413-1-anders.roxell@linaro.org>
In-Reply-To: <20200501083510.1413-1-anders.roxell@linaro.org>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 May 2020 13:31:11 -0700
Message-ID: <CAFd5g45C98_70Utp=QBWg_tKxaUMJ-ArQvjWbG9q6=dixfHBxw@mail.gmail.com>
Subject: Re: [PATCH] kunit: Kconfig: enable a KUNIT_RUN_ALL fragment
To: Anders Roxell <anders.roxell@linaro.org>
Cc: Greg KH <gregkh@linuxfoundation.org>, "Theodore Ts'o" <tytso@mit.edu>, adilger.kernel@dilger.ca, 
	Marco Elver <elver@google.com>, John Johansen <john.johansen@canonical.com>, jmorris@namei.org, 
	serge@hallyn.com, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-ext4@vger.kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	KUnit Development <kunit-dev@googlegroups.com>, linux-security-module@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Zc3KuQRu;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Fri, May 1, 2020 at 1:35 AM Anders Roxell <anders.roxell@linaro.org> wrote:
>
> Make it easier to enable all KUnit fragments.  This is needed for kernel
> test-systems, so its easy to get all KUnit tests enabled and if new gets
> added they will be enabled as well.  Fragments that has to be builtin
> will be missed if CONFIG_KUNIT_RUN_ALL is set as a module.
>
> Adding 'if !KUNIT_RUN_ALL' so individual test can be turned of if
> someone wants that even though KUNIT_RUN_ALL is enabled.

I would LOVE IT, if you could make this work! I have been trying to
figure out the best way to run all KUnit tests for a long time now.

That being said, I am a bit skeptical that this approach will be much
more successful than just using allyesconfig. Either way, there are
tests coming down the pipeline that are incompatible with each other
(the KASAN test and the KCSAN test will be incompatible). Even so,
tests like the apparmor test require a lot of non-default
configuration to compile. In the end, I am not sure how many tests we
will really be able to turn on this way.

Thoughts?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g45C98_70Utp%3DQBWg_tKxaUMJ-ArQvjWbG9q6%3DdixfHBxw%40mail.gmail.com.
