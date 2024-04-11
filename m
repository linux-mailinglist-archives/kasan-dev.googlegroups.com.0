Return-Path: <kasan-dev+bncBDQ6ZAEPEQINBBPAWADBUBGKRMT44@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5733B8A18CC
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 17:33:37 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-56e5c57c1a5sf2609888a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 08:33:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712849617; cv=pass;
        d=google.com; s=arc-20160816;
        b=V0Ak2sWVBAiCcoipkJghrSOrOyh4vgbxWnGgvQbK65WBfE1oqUeTOnxvaBwNm4iEdk
         e9LLNwmaLFtgTs+BHBpoK1WBhAbxR/9t0iqJHAUvpMp1yFa/ql9WFW2TPP/BZ9m1R2c3
         nIDYuQ8iqPnP0Ef8/UP4ZcOavT37exrMxJXzDxbzLmgodVOwje2pGz41fQVlskOh+dqe
         WLZkEno5beyxL5euY1e2k7hFRldQ7f/juoNk1WKUw+eS75MPxpeH/W/SXqiQJKcdroXW
         2XtkU+MVKi2JhXVYiYjdMz5y2w6ssMFLJUNyyz30FckbmeEdfqyNaGZo8tB9jUFWpu00
         Yobg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YxQEsp3PYxlzRa2P+X9drTcwVf2p4Qcma6UxmrDEBUE=;
        fh=Q7wT+5ThIoPpn8aReL90zDWmFK+o0YRVO7q+eRgo7JM=;
        b=SXAg/zKbT8XwgrlvJjvYQd4R5uWWkmSCVhhJoT6JPmqYmtRRGQ3RSwbl2gn4guWAQO
         tuvvHiFXW8qG3RY5VeFve+Qz5b3bho6i2dMAm8ITWXtqfFguZgNqzFzAKmD6/le7FBmY
         GSR5KMg4LlI66Q4xPTKW9SfCWPFia8pyzXdmLwEmo5LH/J0RmVH7Uh6L00al7jYFNSLk
         sR9+SDPvA2bdRj1Z1NRgHgPu/oeKukzlNFKzXxZgzHVuBcDAbi9X7hMUKqNlsQbOTSYf
         53B49doDLNNfZeqwVFm380DgsmD54hmmyrbZNMuoxAiSxuYtYbmcDJ9apLBiXKfSWy0S
         eOZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="RECOPPW/";
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712849617; x=1713454417; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YxQEsp3PYxlzRa2P+X9drTcwVf2p4Qcma6UxmrDEBUE=;
        b=TqzYEUxAAziQutjdPHQHnii4+h+42SyFiULFsXXofqMwRj9V1SHTqe+oBrn1YmXtr3
         ioNuRzYPFt+iFLnK9KJCxR/pIYZXCnvifYDZ+9m3MjHuqPJ/Wgh+f61/ILZVHPqBcULZ
         Rg3qEOU1UPSBvXDtz0gyQQBtDyCL6OTRNSJbInkcIADe2e7w54kQyAOJlCkyO73eQWF9
         OPs+TG+iEvpIEcBGWTBgodNr5KjT5ISwDtYatMwDjrYMGbgJxIBq7HCpQOWw3uxjICod
         RCkeuSRRKGf2sF2Tbo3GwvdLrjYidjES2M+SAFsFgynrBOmL1toUWF3pehdmtbxoxgac
         jTpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712849617; x=1713454417;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YxQEsp3PYxlzRa2P+X9drTcwVf2p4Qcma6UxmrDEBUE=;
        b=bXvusKlbipmyj2sCUZ4bVg8M5baOWZUDtU/E6MfEGIopoZl2qoxcfQzwOqV+/VeGEO
         sh61XGEIvNpcufSfc/oJoXqpbH0EjQalafV3xqvIyZrmym538/lN1BoiAsGnA4SbVQRp
         3b+lbLdPmqamjQUBsSZbkYKTQ0xxIvz7zMfWTlfI+e7Jz7IJDaf76qKgWxCFgtPRXdJQ
         mkVEgk41KvdtBpB9+CQpiXKBqpqWO3QDl9zTVjO9BSN7Fwrs41QwqpmnH2ywB8TkO3rB
         yNO7OrcG8m8frwjFGIgtamT4Jd9nDiTByTSfqWZgJxmGQMcx3rhRnwQOYSWQNooexdhZ
         yr3A==
X-Forwarded-Encrypted: i=2; AJvYcCUi89tBWD6Hd3QQBkFyrYNExW7SJW/M5tvi8y8Kgwp2bt8eKfqcaSp/LpY8icddwMUnF1oWDoepgTktgc/OU9WT0rvtpIU3ww==
X-Gm-Message-State: AOJu0YwwxApoNNyuIPjPES1AgbikYFZ4dkyI11+HK64FbsERrh7g7VTu
	oS7FaYNLX5A7W9v8WoDOtWALaEau08UfQMbaqPxOKzhiWLv+gHxx
X-Google-Smtp-Source: AGHT+IEMUylQMrhRu4LQoSeFszvL+gD7kmqG47sRDe1FJdyaBuexClhkoKUDAGVdQBPFI3DK5USZfw==
X-Received: by 2002:a50:9e4e:0:b0:56e:2d93:3f84 with SMTP id z72-20020a509e4e000000b0056e2d933f84mr120413ede.4.1712849616450;
        Thu, 11 Apr 2024 08:33:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5306:b0:56e:2ab1:dc5d with SMTP id
 eo6-20020a056402530600b0056e2ab1dc5dls282390edb.0.-pod-prod-06-eu; Thu, 11
 Apr 2024 08:33:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVx51SXGetevys6PVoQpvC/Cf6knXU+ud3gC88KICsp4/SRmfQia4vlevVA7gX3XNzjx5SrZv4tcg1YAjVlqjy5h6tbdM2vR7L6Q==
X-Received: by 2002:a50:8e10:0:b0:56e:246b:2896 with SMTP id 16-20020a508e10000000b0056e246b2896mr128592edw.3.1712849614180;
        Thu, 11 Apr 2024 08:33:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712849614; cv=none;
        d=google.com; s=arc-20160816;
        b=Hy0wsZZF6c3C6bCLjoPjuV5tSJpv6l13Mc0uXN6MJi/CsWjK0W0MAYLj1++qo2BBGD
         aWJDUkJrgYF/Rby/wCnf33iDAbdsD+xU+ronID9bM/wpZx4eA7sN4gofxDXYgCp1skoi
         yDtfWwY2gXoirSoa0yA0OuW9hKn4xywwjfQdYEgYEniQyvxhydreXZM+uOsePu3EW19Q
         /1njJBKdwezd9P5B7hjfUvxGspAZHzTibVtiYk1PVEr9036WxA79wjYtv0ohrB0ORpvN
         TVdg0k3kX4tYyJpa5e1Uv2abCjN1mM5/OEDtxUA8yOxKbIpSIiAqLy/UQ/xzNz9F7txh
         PPPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WWEKgvL/ZOpKjtTgIwws6qhc3HHfgaLuekbpj/jm1oc=;
        fh=W49IbVR0XYYvxUoRVsu5hPKaNLw6GGNMOX6xaXrFuHE=;
        b=v6mvp5slpMeET4WuXMa5TIIfqetAskcSQU21EvHwuQFnh5kBRllgXcX8TgmQZycnEZ
         ZeKirdFV9YKS/5ddLN6w0hgnP3SuETZSS1PmZNC9iHARk+UwuIrQF/T3TEzyhzzQjqp+
         BVRzUhEHHZ3HUwWPAdBepDHJzSXsjGXY+5uQ/tY5s3vauoIBtVc9odhk4WnmzFiZDoTK
         h/k3zmH2X1mjcs5eZLtPtRh1+W/GFiVHDblycz8a8s+ojlQcGtaSuGdJ9BW6zSNLdRM3
         NoRjuOpSL0+OTSYBxPm9BWZwBAfvrl6bkqkLClo6o/AaiDUKbKULUQ7P7FX49n2J8Itk
         80uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="RECOPPW/";
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id m9-20020a056402510900b0056e79752496si48610edd.3.2024.04.11.08.33.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Apr 2024 08:33:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-41699bbfb91so95035e9.0
        for <kasan-dev@googlegroups.com>; Thu, 11 Apr 2024 08:33:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWBuDNXTJTHUXpqQ6dln9XpMYTPntIxMZ9w7TaCRoKiZ1lmx8G9CIs7mb2Qp1os7aYpQgPT4gGHmyoW0rNvcOel7HyuaJm7d/M+Tg==
X-Received: by 2002:a05:600c:3b93:b0:417:3f9e:5cac with SMTP id
 n19-20020a05600c3b9300b004173f9e5cacmr177314wms.3.1712849613449; Thu, 11 Apr
 2024 08:33:33 -0700 (PDT)
MIME-Version: 1.0
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx> <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx> <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx> <20240404145408.GD7153@redhat.com> <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com> <a9a4a964-6f0c-43a5-9fa8-10926d74fbf1@sirena.org.uk>
In-Reply-To: <a9a4a964-6f0c-43a5-9fa8-10926d74fbf1@sirena.org.uk>
From: "'John Stultz' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Apr 2024 08:33:20 -0700
Message-ID: <CANDhNCp=7mTSSO4cXQjYbtLrK8XRCbCyse8Bq5Wbt5V4G-K_dQ@mail.gmail.com>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement check_timer_distribution()
To: Mark Brown <broonie@kernel.org>
Cc: Oleg Nesterov <oleg@redhat.com>, Thomas Gleixner <tglx@linutronix.de>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, 
	Carlos Llamas <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jstultz@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="RECOPPW/";       spf=pass
 (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::32d
 as permitted sender) smtp.mailfrom=jstultz@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: John Stultz <jstultz@google.com>
Reply-To: John Stultz <jstultz@google.com>
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

On Thu, Apr 11, 2024 at 5:42=E2=80=AFAM Mark Brown <broonie@kernel.org> wro=
te:
> On Sat, Apr 06, 2024 at 05:09:51PM +0200, Oleg Nesterov wrote:
> > Without the commit bcb7ee79029d ("posix-timers: Prefer delivery of sign=
als
> > to the current thread") the test-case fails immediately, the very 1st t=
ick
> > wakes the leader up. Otherwise it quickly succeeds after 100 ticks.
>
> This has landed in -next and is causing warning spam throughout
> kselftest when built with clang:
>
> /home/broonie/git/bisect/tools/testing/selftests/kselftest.h:435:6: warni=
ng: variable 'major' is used uninitialized whenever '||' condition is true =
[-Wsometimes-uninitialized]
>         if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor=
) !=3D 2)
>             ^~~~~~~~~~~~
> /home/broonie/git/bisect/tools/testing/selftests/kselftest.h:438:9: note:=
 uninitialized use occurs here
>         return major > min_major || (major =3D=3D min_major && minor >=3D=
 min_minor);
>                ^~~~~
> /home/broonie/git/bisect/tools/testing/selftests/kselftest.h:435:6: note:=
 remove the '||' if its condition is always false
>         if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor=
) !=3D 2)
>             ^~~~~~~~~~~~~~~
> /home/broonie/git/bisect/tools/testing/selftests/kselftest.h:432:20: note=
: initialize the variable 'major' to silence this warning
>         unsigned int major, minor;
>                           ^
>                            =3D 0

I hit this one too yesterday and included a fix for it here:
  https://lore.kernel.org/lkml/20240410232637.4135564-2-jstultz@google.com/

thanks
-john

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANDhNCp%3D7mTSSO4cXQjYbtLrK8XRCbCyse8Bq5Wbt5V4G-K_dQ%40mail.gmai=
l.com.
