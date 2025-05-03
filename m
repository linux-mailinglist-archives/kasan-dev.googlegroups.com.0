Return-Path: <kasan-dev+bncBDCPL7WX3MKBBKND3HAAMGQE24Y4U2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6022AAA81D4
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 19:26:03 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-224192ff68bsf26306115ad.1
        for <lists+kasan-dev@lfdr.de>; Sat, 03 May 2025 10:26:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746293161; cv=pass;
        d=google.com; s=arc-20240605;
        b=eWWWMUVDPE9hq59+1FMkWVFKmzPKxUwgTYUeMrnsBWy37qpxUY9XEeUATudqV112Vv
         vc2/r5t0kr+jGq4ZHZdRFjQ/tHzfgeoSy59WQjJieIjRb8oGXD0yG/0BMQGlOKhkfTK2
         nObcAaXZBDW+/cCpLXOxCgC+WYAjrJXZaCIx19sawipR4Mxqzdy5snOH7hho0T612G9J
         xt8FeUu2Eei9dWJ5+uQZxrwA89DBgvL6tDuaAKf7HUBNa+6KPog+oEuu+UVFsypdjRwd
         GvSW6TlfmBVYC2H7OnhU6DVcG2nsoL4c1fGAbqE+PRdyBeD/FHeuX/aL3Ch2q60mgQdj
         b1Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=UkHan+k4MGS9r2CYXkAFeKrxsY83lNSp2UqmSlW36Uk=;
        fh=fxOE3ALwUVKuU2bMlyINIXdfWiLOKVIR+O2G93VCLTk=;
        b=aKgyVV1tKOgbF1oY52lDx5VkCO7glYasr8Q04dKpwIWt+oUnWoWrWgimbUsWFb0Xe2
         OM3XLSxlXfOjdpsxkdZsAETgwdbIR0Ow8y8eQ5VXDJRb/bRYBbAje58xU56Ez1VkeYg6
         Z/sN1BbGUJHrg2I5yCaQU5rVfR1eL2Dw/6fbyaXbZnT7R1oXAiWp1SURJmk5+4I2fwzH
         oNr72jIH+2QDF9bVnkcjwO+uTCApuqyuTRkqY7TpNK2CGxulWXg7xNpmyTPlGL/JzxyZ
         yAyHbScWvYH+rJ/5xK6y7Men5y5QxQMOlolv3FbN+VRYDBixOZRxJXdRhK1ltzCdqqX3
         RprQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JdNJhVm6;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746293161; x=1746897961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=UkHan+k4MGS9r2CYXkAFeKrxsY83lNSp2UqmSlW36Uk=;
        b=R9nkbcmS6gF3nTOFYZObbJtB5y4p2jlxsUG+thjPN8q5deGNcEBt163w+LF7yoZRR9
         CO8tXnWESbEZdJOpNYROy34rT+rhVCeKjMC0XGISglOoGLtxBXOzafPJKkSkkkwIxc8+
         aaK2pHT5RGVeuiiJU6QI/YZxWOAz6LFf/wovwF86Xrw7CvYdagP8CYZZ9vKOEAF4mRRd
         2zfjsMTWGgVVeNMbsj9jQqVxs+6stbd9SUlUB5nsBPwU+ljI+pOKC3fUnTVqS+o0FXhx
         7qIy9CjGYIjqQhvr7ynkd6GZZxTUDS/VJaoFnaoi2hW80SCnhn5Q0xFTREoBFpGRaweI
         XKXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746293161; x=1746897961;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=UkHan+k4MGS9r2CYXkAFeKrxsY83lNSp2UqmSlW36Uk=;
        b=ZMPKWlGuDhJXmepF9eYsdPgXwyOufc7wbv2fKktAKNKJrGcPxyKvs4r+f0WN//h8ld
         K2o2FBxdyCXk2UlF5iDhTuX2WtU/ZKT8FSLEWWlNHrFp2i1/pl/ZWRTCu5yEAjaeWrCT
         WxHhuAHfLGwciUwcnscuWTQK8EiO6ihFP/xAhWUNUAAPIY1o9rI4nTcAzSg4XkthuEYV
         bWVy9R5PMCgolqHMUv2nCDImyQcZKUCbYcVpK6ZAnxTRzwt1U9fyoghA1kuqtm0p9lQj
         o3urxBvwpwOkRw92KHmGt0ezS7wJR0uecFSZjydP03e9ZCUlgeRNGuIo5Su9leDV7CrI
         aDng==
X-Forwarded-Encrypted: i=2; AJvYcCWforDU5MHQD3l3i5AZXXtfc8pDhQOXMDogiAWqyhHg4L72i39ysBOi6juNG7LOUyZeJ5VQKA==@lfdr.de
X-Gm-Message-State: AOJu0YwkPtv6f1mo2IJGIISzigg+DAW2o/LJAxAudz6ZHJXganIMxbBp
	QBN4w5AiSgOyyzFhuWopLsy8vg/1m3RVSZ3CkFOB2X8pXUUEgUCH
X-Google-Smtp-Source: AGHT+IG99PJ+r4Uu7gFRxORWRA7WOI+mgGmj85mET0st9Z46NOU8/Euaez/dXGaMcxTLYKj01oZYBA==
X-Received: by 2002:a17:902:d48f:b0:224:78e:4ebe with SMTP id d9443c01a7336-22e18c38f2amr49490655ad.33.1746293161520;
        Sat, 03 May 2025 10:26:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBF5t+cmRrHSHlWEHlHCh3mC9ogVSVk8sl0hSGCsWV1BMw==
Received: by 2002:a17:90a:d48d:b0:2ef:9dbc:38e5 with SMTP id
 98e67ed59e1d1-30a3e74e7bals1985449a91.0.-pod-prod-02-us; Sat, 03 May 2025
 10:26:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcuNTtz3Lzq9XcCRz8uVxpLRItA1+pRJcUZtAT0Cd4dKtU2rqMtKTt3FbTF7MGPSyEWC8A8etFluQ=@googlegroups.com
X-Received: by 2002:a17:90b:56c4:b0:2ff:6e72:b8e2 with SMTP id 98e67ed59e1d1-30a5aedb81dmr4918696a91.31.1746293160217;
        Sat, 03 May 2025 10:26:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746293160; cv=none;
        d=google.com; s=arc-20240605;
        b=KCKpdCHF2msNjA8uthS+eUE5xRdOnhOfCC3LA5tSxV2/UMw5UsjL8lJ03hxlIYSXgK
         XTM8+WmKQ4kH2HIMhVkfo6PnKSpz3K+QRT5F7PTWCre2qbTe2qZekTtqHsr2OYZU6zQq
         kFMum7jljN9QuVX2aafer2WWOdEU8rFAr09O0LvkXQyyZwYfA7Yp0vpj4w2dDMYGicfP
         tJz6VaWN1M1UAuNZTQcJCUEqRm07s43Zi6GeVpjZqUOfpQv6U+ytcyzUiyuPKEr9GdcX
         B4nibS14ehuxgwCldjFMThSZAY0Gi49zjjPPfmfmbIb1kpTAe8Z7N7I0lyCAJCZc60MD
         6seQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=KbziGNtfftB9OXRbFz9eW2DLtJiSLq1EL37Tz41iIJg=;
        fh=soCZi0BV5pQxu1QUAmIYTvX3VGBc8btX/HyeeXy1AC8=;
        b=hE4kRbk8fQyZuIXnB0ZsFTDb2/FDihsYvbj+8/dZmWNKV5CuRNxVLwNRlwsCnAVSpc
         98h6g+O+UN5JK9v7iwd9kiIaT5szE/sq9p6H/eHGdViPMcePT0GDQFpTYRan4z7JMxh2
         0lvKLMvU9iYanXuXXuhKlMDlfBFwYfXpbIgZcrEVco1yDsi38/BmVmJWIssB9WcsA3SE
         9oIwxlGXctr8PuMBW0iWUKfS1v2hU0yf50gx83NiuJZApm3DpgQZvfNQUXjDLSogqrI9
         17aylT1Owc4jj/OsjrXqwEw6prhD2jeBWUrhauL2IWrDkeLHxdGRtCMlIXr0VOBV27fW
         Y9Mw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JdNJhVm6;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a263eacdfsi793944a91.1.2025.05.03.10.26.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 May 2025 10:26:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3BFD04A050;
	Sat,  3 May 2025 17:25:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 80E39C4CEE3;
	Sat,  3 May 2025 17:25:59 +0000 (UTC)
Date: Sat, 3 May 2025 10:25:57 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-um@lists.infradead.org
Subject: Re: [PATCH v2 1/3] gcc-plugins: Force full rebuild when plugins
 change
Message-ID: <202505031023.BC44DC842@keescook>
References: <20250502224512.it.706-kees@kernel.org>
 <20250502225416.708936-1-kees@kernel.org>
 <CAK7LNATs4uHnNHgESXcUEjpONZra=GvkuHMaDwsx0hbyUGY99w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAK7LNATs4uHnNHgESXcUEjpONZra=GvkuHMaDwsx0hbyUGY99w@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JdNJhVm6;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Sat, May 03, 2025 at 03:12:23PM +0900, Masahiro Yamada wrote:
> On Sat, May 3, 2025 at 7:54=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
> > +quiet_cmd_gcc_plugins_updated =3D UPDATE  $@
> > +      cmd_gcc_plugins_updated =3D echo '/* $^ */' > $(obj)/gcc-plugins=
-deps.h
>=20
> I think 'touch' should be enough.
>=20
> If some plugins are disabled, it is detected by the normal if_changed rul=
e.

I kind of likely having the active plugins show up in there, but yes,
"touch" is enough (it's what I started with originally).

> > +$(obj)/gcc-plugins-deps.h: $(plugin-single) $(plugin-multi) FORCE
> > +       $(call if_changed,gcc_plugins_updated)
> > +
> > +always-y +=3D gcc-plugins-deps.h
> > --
> > 2.34.1
> >
>=20
>=20
> I think it is simpler to place the header
> in include/generated/.

I couldn't figure out how to do this, but thankfully you did! :)

> I attached my suggestion below:
> [...]
> -quiet_cmd_gcc_plugins_updated =3D UPDATE  $@
> -      cmd_gcc_plugins_updated =3D echo '/* $^ */' > $(obj)/gcc-plugins-d=
eps.h
> +quiet_cmd_gcc_plugins_updated =3D TOUCH   $@
> +      cmd_gcc_plugins_updated =3D touch $@
>=20
> -$(obj)/gcc-plugins-deps.h: $(plugin-single) $(plugin-multi) FORCE
> +$(obj)/../../include/generated/gcc-plugins-deps.h: $(plugin-single)
> $(plugin-multi) FORCE
>         $(call if_changed,gcc_plugins_updated)
>=20
> -always-y +=3D gcc-plugins-deps.h
> +always-y +=3D ../../include/generated/gcc-plugins-deps.h

Aaagh, thank you! I didn't even consider trying ".." for targets!

Yes, this is SO much better! I will read your other replies and work on
v3...

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02505031023.BC44DC842%40keescook.
