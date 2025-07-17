Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPO44LBQMGQERTJAH4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AE41AB0877B
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 10:03:10 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e81a449767asf930287276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 01:03:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752739389; cv=pass;
        d=google.com; s=arc-20240605;
        b=gqyIO7DNC+/PTd9ea6TcV52jrQyWgGAyK27RUWyxvzjXIdwgsOmTOopXuJ4IaZll/s
         6Hlwc3Z9OJIa+Nrn1p5lD0yGa6R2LTc7o07VdcLb+wn3cEo0vBZJNjaHQZqbUQMPUz7A
         kxZkg3VX003KkSSXn4DOOdV24eHFldxjbzH/ATqCFwSzy6L8o4eHRC2FmJ5/dBZEUgZ/
         eEu63w4SeEZIvI/MXNs+lmidrpA9GyGJLqzzMk0e+a9jehl2mGprMheRctIpmhlC0L9J
         BoJgZRPy0SoYLlCqZB+08eJ4ilqfPXE0PKecCygtUamt+QflgPtR84TfDeV60638lhGn
         saSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A/msKKZO0nYtRl+oVC42I7OmvvSAK8AbORSJ7+FEUnk=;
        fh=TDMPPfeRBCA0stX9l2hjKxGz3dpP3+TYYkAXeT/Ubu4=;
        b=ke22MJJqjbkKYI9kDqCgQt8LnfFGze4EKczSODm63GPQE9fdXgzpNj+XzMg6A7QZ0w
         HPHZGAMvLtdVEUuelZh9Fn9iC63HLnLISYbxVsmHniZLvza4Gq1fE7VRXsciLtXI6itL
         thZa8jzP+NgF8Y4R82U5ebyqedx09zDC8BJke1vuaYSgCo3QFQCCpuryydsl57swQTHv
         IRdycg6u2nCWlGCmSKbM+eYHL2lbcRkpcYjktNxomO0BKtcJ/fXG/A3zCoYhfU4SKW+2
         FOer503kHxTjSRh8cLHJxmb12oKqvOwr/571rccjFTc7ItynxlBMRxr83vhVVIAlRFtM
         C67A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=phNYi4dg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752739389; x=1753344189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=A/msKKZO0nYtRl+oVC42I7OmvvSAK8AbORSJ7+FEUnk=;
        b=YhHUsI05T6v5GEOWKznwrwCiXl38EUq1vK4/0ApLMbaF7SMBzE9qZinMyjl+uRBNG9
         E8ak36Gzm9p4dsxbbCbCXDkDSBaK/lsnz7+LXhNtaAw9Ub3CzRRqFKSe2IJTYD6aa2kl
         MoNFzNUEZW3XVwLe8IlpRQeZwgcqqMv8yeOaSfAKv4b//nbtR5WAqpwL6j6hfK+HH0XT
         BjEF62KIUzEJogkAdcHUng5sP6HMjdSrnafQWhltFOm0BIXAS+Yxkzew8tk5Y16uZDZy
         HVnJzcutpAJht94veHOb7ToCheHdS559GDjZ5k66DL7NkucCwb+wosc5+nxwMPybqWhD
         rbeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752739389; x=1753344189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=A/msKKZO0nYtRl+oVC42I7OmvvSAK8AbORSJ7+FEUnk=;
        b=MNYHZyVX6n70ANqynlabF3TosfRLMlDQFWaoR6wx/5Hg9Pllv1/T//yb+V7yIpuo9i
         ibbIEng1n5kc4DqlDyluhuXv9Hp7tGVoMiEWIZcHJY/WxVvHhw2D+NWUNpw1Mdxp2tMM
         zSBOH+4FcR0LERPL6bfX3Of15Dmf9xz7KrfWt/S+nMJk44F5KV+SdqxZcD/sff6+TEWN
         NRqRaPNgcZm/BkzccQXtCanAZfleBKio6sdA820cZfTRtsSyQ30Qu1975RorOAW3poZZ
         Q+ratYHdaEPSxdowMQTOh4Rercjw6fdqGg95UWlhkNOzOFjaKebM1SQSBBBs5WW9EaBf
         lE5g==
X-Forwarded-Encrypted: i=2; AJvYcCWXjtbTEbltXaUclBwPcTq2zFn2A6foPFbNrUJGcIScs/lMQkJc1BkZ7RoM55ZcLwp6ReHNbQ==@lfdr.de
X-Gm-Message-State: AOJu0YxYluGO0RA+jKpYAXIc+3ROZw/uGAROuqRbfg198HYweLBnNqKv
	4kQh2DElHqCmZij16VQxRmqcSzorYmg9w4sXKx/88nkid+OyJ0N66H4G
X-Google-Smtp-Source: AGHT+IFAmL/0rCmYZOh5zfGxi+PRUUkEbEGcTNKtVt9I+4OznP6Uz8pZEYMMlG6JB256Jp0lPrZGhg==
X-Received: by 2002:a05:6902:1285:b0:e8b:d2d0:8b1c with SMTP id 3f1490d57ef6-e8bd2d090e6mr3677374276.42.1752739389245;
        Thu, 17 Jul 2025 01:03:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcnhW4/nS4VssEzGKN8aU3tzVV9XzU5g0fg1GOwW1PcAQ==
Received: by 2002:a25:29c1:0:b0:e8b:ccea:f31d with SMTP id 3f1490d57ef6-e8bd46b3ca8ls765649276.1.-pod-prod-06-us;
 Thu, 17 Jul 2025 01:03:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPhw2Qgv0Cxo032FXb7Tru1TWueKfaLSspUn5ns1s1F/q0lalV9+ReBd6YV9fygHC46GXHj+S9J38=@googlegroups.com
X-Received: by 2002:a05:690c:530b:10b0:718:3992:9145 with SMTP id 00721157ae682-71839929454mr49013947b3.41.1752739388449;
        Thu, 17 Jul 2025 01:03:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752739388; cv=none;
        d=google.com; s=arc-20240605;
        b=IQvVetFttDQPNi9thmy4/AX+B0G0EcqwN4tvDhZmpjIjp9GxYnDVOvSk0qFBFtWTEt
         vZ67HaPaNuO8ZJE/SbEsDMBcRfC+wC6I+rVjGvvQog4i1s68eskuNqn0GSpi0AR/UtXi
         TqOG+OOLLn1mfqbnw6qa/etdu/SrSnoC8Pl/xb6GsLYFwATvwBvhu9ZkyRYfBXcl/sGF
         YQnZkHonvHRt6N4ZgxjeqE0c77SWekeKSjrn9BiGcsb4E77MPCACegVt/aF41eGC51aJ
         YAOfA2wl74Bhzageh3IEClKH8QUgVjM4FxGkcd7Vulsr5vY0MwQ3lYUIVW8mIyupxz7b
         9ToQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UvqTp2Zne68B8LzixST7+FuqQVUNyNbaJiuvHRRCg6w=;
        fh=mzGRUZ8VOzOn2bZ1Jdaa8iFS72DXwbUwGUEymCynfsI=;
        b=JB/A1/26oWZgZ2AXUsab6DijlxGmY3wBkFWxiblj/wtie9ZJ1kyB/OgZAjBLt0UHlg
         nIBJbEpka07jd/odD0lNcVYOL0Wbs4+8yPgCIjFkDy9FQ50gYMA9Np3U6TZ5lwB9KZ00
         kTXf1PJ4tpQ27wI8TgtuuBoaKLOwoUvSnmAiRJDh+aV6GEG1xgF0NnR+xaAB81O1nGzo
         /qCQrNlA6tDABmklZogB+vfRjaw/BAuNkefqu0v+asbsqhhvwEb06+0b/So5XdwWdjth
         IpowlhlaR0pHOKw0HvXNKs8OkI7SDyPyZpmjhOUV+a5HtoJ2uIZFKV+RJ9+RMM+N6Jtb
         opwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=phNYi4dg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-717c614d5ccsi9455467b3.4.2025.07.17.01.03.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 01:03:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-6fd0a3cd326so8882966d6.1
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 01:03:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVbF7T3yYKH4rNX29Hu7LkuqhEhIJv4+wZErInUSKfSVJGQF3xsZdEcWG9+d1JV5x78z3e+pZ7/o20=@googlegroups.com
X-Gm-Gg: ASbGnculHA5DIH8LBtR1xvKjL8ZzgZxx20JIwfmo6Q1oBToeJ7N3PWq6q/YAWeQrKEJ
	C9F67NlpEEnrIhnS+zDchEb4WPJLeK/LGawJZ98LkMWnuRDhPpIMfVvfwbZD3O8+T1QMeH8BT2s
	NYO5CasfbvnOa9a/stbXs8rTgJycATTTQJB4c09JxOVw5jSuhHbnx3+ycqcb992QKZvivzCSA+E
	P2KJeBEAWOfwSjlzvRCkfd3efVzS3IfN1qj5Q==
X-Received: by 2002:ad4:5d43:0:b0:704:e0a9:f815 with SMTP id
 6a1803df08f44-704f6aed334mr84550186d6.10.1752739387636; Thu, 17 Jul 2025
 01:03:07 -0700 (PDT)
MIME-Version: 1.0
References: <20250717024834.689096-1-sohambagchi@outlook.com> <CANpmjNOu2bqqevOcPGmZR1Dp69KFY9-TW3i2i_37BCTcE5rYSg@mail.gmail.com>
In-Reply-To: <CANpmjNOu2bqqevOcPGmZR1Dp69KFY9-TW3i2i_37BCTcE5rYSg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Jul 2025 10:02:30 +0200
X-Gm-Features: Ac12FXyzyEXffumt-s4OhbkbAxba49Fj3GMtu0oU4c_K0t_UFxZZ3n-qtDrjZ9U
Message-ID: <CAG_fn=VXnaMitRFpxP0Fjy=vWF+rjRfZ0TRsziwKzEVrArXt7g@mail.gmail.com>
Subject: Re: [PATCH] smp_wmb() in kcov_move_area() after memcpy()
To: Marco Elver <elver@google.com>
Cc: Soham Bagchi <sohambagchi@outlook.com>, dvyukov@google.com, andreyknvl@gmail.com, 
	akpm@linux-foundation.org, tglx@linutronix.de, arnd@arndb.de, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=phNYi4dg;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Jul 17, 2025 at 9:16=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> [+Cc glider@google.com]
>
> On Thu, 17 Jul 2025 at 04:48, Soham Bagchi <sohambagchi@outlook.com> wrot=
e:
>
> Patch title should be something like "kcov: use write barrier after
> memcpy() in kcov_move_area()".
>
> > KCOV Remote uses two separate memory buffers, one private to the kernel
> > space (kcov_remote_areas) and the second one shared between user and
> > kernel space (kcov->area). After every pair of kcov_remote_start() and
> > kcov_remote_stop(), the coverage data collected in the
> > kcov_remote_areas is copied to kcov->area so the user can read the
> > collected coverage data. This memcpy() is located in kcov_move_area().
> >
> > The load/store pattern on the kernel-side [1] is:
> >
> > ```
> > /* dst_area =3D=3D=3D kcov->area, dst_area[0] is where the count is sto=
red */
> > dst_len =3D READ_ONCE(*(unsigned long *)dst_area);
> > ...
> > memcpy(dst_entries, src_entries, ...);
> > ...
> > WRITE_ONCE(*(unsigned long *)dst_area, dst_len + entries_moved);
> > ```
> >
> > And for the user [2]:
> >
> > ```
> > /* cover is equivalent to kcov->area */
> > n =3D __atomic_load_n(&cover[0], __ATOMIC_RELAXED);

We shouldn't probably suggest the users to use relaxed loads either.

> > ```
> >
> > Without a write-memory barrier, the atomic load for the user can
> > potentially read fresh values of the count stored at cover[0],
> > but continue to read stale coverage data from the buffer itself.
> > Hence, we recommend adding a write-memory barrier between the
> > memcpy() and the WRITE_ONCE() in kcov_move_area().
> >
> > [1] https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tr=
ee/kernel/kcov.c?h=3Dmaster#n978
> > [2] https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tr=
ee/Documentation/dev-tools/kcov.rst#n364
> >
> > Signed-off-by: Soham Bagchi <sohambagchi@outlook.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVXnaMitRFpxP0Fjy%3DvWF%2BrjRfZ0TRsziwKzEVrArXt7g%40mail.gmail.com.
