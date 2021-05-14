Return-Path: <kasan-dev+bncBAABBUWR7OCAMGQEXKHTACQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 362843812BD
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 23:17:08 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id s10-20020a62e70a0000b02902d500c920f7sf472572pfh.12
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 14:17:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621027027; cv=pass;
        d=google.com; s=arc-20160816;
        b=zSTXc3IKMrA6nEap6jQGgSaCt419ip/J5UfzLf/PsO6ANGoHAdL0chf8LXloLPCpZl
         BxlmbgrPKCPcmm0S31ZD29d0BOLVCw6iHoxXtu2bY7M7emfnX95MMIcFCw3h8f7lI6lD
         KzjkZC5diUcB9BtUZatG4/4FR+EMmxaWbbREg+ZIcRPTR7uNnKW8VSpVKiZ178eCoOrZ
         xA7PwjQnuyqSeRuNQRi9sNtwtqPiQBl6ijo6ODkI80e8nkrgYNVbInk1AWgdvscUS0Hn
         JwjghbFrFYYMhaTBCzR0tNftZxqw20gO2BeW3DQVC3vKxATva5J/zt113saKqeF9PfbE
         sY0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=6Mzw7xQ6RPLDLL7FbytF1lIjL79wOfFbM4RbTMftrLI=;
        b=NMmgBJ/JzUOkBdvICpFu1nvilOmaV/gfwS1ojKy74vKOQoGoSnoAJcRdUMBlq+zhb1
         gUVsE7yNTsSOmUPr0QFkXbxCgOlQkMEBUwNzAvFXWPB5W7w4of80uEW5MKKnjZc6RS9E
         +m1OcHYOeYA6elPNixMEea9oD1+ZKjjTy6RVGlZofB2bwuMD+Vi6Cia55ohpLR2cMjby
         u15V490GyYqbDDFGFTP/HUqbzj1r7m2X17YuDfr+FnqVyMVVcwvqm/VRrWmAaWflq/hU
         TJ065JXhy+GZCgRlPszppaE5Uc1f3ZHFi1MYaIznNb4dxu/sEAOKrN+LCr9M3QpuIN9v
         Q29A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="oy/zU7SW";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Mzw7xQ6RPLDLL7FbytF1lIjL79wOfFbM4RbTMftrLI=;
        b=nS6ETBbvS3dDv+JIwpdlM4Jk8fBmRWcNBUgjcLsS/j3qhq9ugDmSL/OhLbuE1eeHNv
         8R9pag8ADuxIydtFCepBS74rSesPFq8XIHYqjI3X1RzgYsZLswbHXqcvSSmdrszgIjRt
         UfEb/sPne7TVFq1lciE4gD/OFFdfvdqJmVWSAXjD3SviecoWJApUkyegKSnQspSy1r8Y
         rhD+HNbRBu4OEaqusk4Kum6JrHdrXC+NySWg8oyTnoqcO4PiYTmZV4aK1hfOsU/2IT9q
         kvdPVy/No84ogg5ss02S7c08SjFkVWbpjNv6vHF++Md5xncGXkJq/gTKOq/M/HveXaFz
         968g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Mzw7xQ6RPLDLL7FbytF1lIjL79wOfFbM4RbTMftrLI=;
        b=ohB0oWU5/8PRPbWAEl9sMqNgvbBjqLN8y+khM4ye1VcOIHjOmfWCk+5a0+mWurL5Iy
         PG2ttrAmByOcD8ubGVk+kJKOAorRGumYqz4bvbGEYD2KrpKuApKcFoCbDnPICq/FEEd5
         Xu7dfHAkwEeAOAI3OPr1mx8fLQSkkRqviIxs/skcCJyti8zuFRuuohfOXu1dHTc20iXM
         BQTdVhQ7zOvYhK2dbD22PehXpCOSlF1avYzLm7P0VB1+8YdrLsjgnFq6awzizqI7Asjf
         o5QykbUJJlzJdkURgYtJbtcN0KOHWmJIxZsS7Fx7ygGEuMMuIJT7lTu5mrhOWZ6U2cUj
         HOAw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DgQeEgcBueJGkLDuuDMvK8j4LXYsnjQHnoP7t699pHazh1jFi
	ehvmw2+CtOhDxQtLBLaGESo=
X-Google-Smtp-Source: ABdhPJz5kqhmw2+vYZ3KIhYonYJdEMXfXXah1LW3iyt6zDFrvDpsf3etjgeiuuUUu2x6xpuOdceM+w==
X-Received: by 2002:a17:90a:5995:: with SMTP id l21mr12957288pji.79.1621027026940;
        Fri, 14 May 2021 14:17:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:860c:: with SMTP id f12ls5544176plo.5.gmail; Fri, 14
 May 2021 14:17:06 -0700 (PDT)
X-Received: by 2002:a17:90b:17cd:: with SMTP id me13mr13428049pjb.128.1621027026391;
        Fri, 14 May 2021 14:17:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621027026; cv=none;
        d=google.com; s=arc-20160816;
        b=uTQIsrTcs7OOldsxT5NISY8+BHgYHg9ZIoWKvWxdkl/GL5JamUB1P6rgqWID7YIlwb
         PSiZFJ5rhdSN70MrD5oOn/mx5SlHsyklOOxt4WdiQfQvd9yAwuvIffR/Uw1aQ5JVwwU/
         c369m/nzwWKNkKqgOVDIRPTpesBF7ffyv9IiJmDZO7xPYD3pPwnalX1V12f/k7bcmtXw
         OB+mhr3dz7M9vDbwimdTaGn+KERQMMmO1fcZxa1+Mh6w20mQjapopxbbRG5zz6M8JX1J
         jpnOSDiLi9gwP0ELxns7uBkOVl/xaDn8pXOY/ZyP2NMAMWbKbBmCV0Uwf0mbxVcbzMFH
         Krqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=41zkt2dIsP5TA7+eea1zwunYrwnck7oBuHHnKiPfLEY=;
        b=rf0W+etY3SejlIP7ZgxofhYjbFkQzUShRZyvL/wIjKR++ip9b6YMXJvjROopMuLm5D
         eZDa0F7ZVL/2A/4MsS/+jygLRveunD4bU3mZ+P8jbF40uEvJ+djW9EEeQv2g/rbrhZxy
         s967Uu5BzFARE56m3QGmKtaaLzDW89b6TIixSnseKQ7R90ZE1M6AxBZW/inFpKahV03f
         WQyT5pLUvyy9S40cOjRxihzEqWg29tRUTMEdF+PwP7R2WMBlicZIZ7SL2/cNYhMyTiiJ
         CH2Xlp1HZJwA6v64LF+74CpiTvOAS1EI9BNWzLinFkzqd4sQqbf4iVm6HBGCk0P2RUiM
         KXEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="oy/zU7SW";
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a6si485874pgk.0.2021.05.14.14.17.06
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 14:17:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1D7B061454;
	Fri, 14 May 2021 21:17:06 +0000 (UTC)
Received: by mail-wm1-f52.google.com with SMTP id a10-20020a05600c068ab029014dcda1971aso2021322wmn.3;
        Fri, 14 May 2021 14:17:06 -0700 (PDT)
X-Received: by 2002:a7b:c846:: with SMTP id c6mr11049940wml.75.1621027024776;
 Fri, 14 May 2021 14:17:04 -0700 (PDT)
MIME-Version: 1.0
References: <20210514140015.2944744-1-arnd@kernel.org> <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
 <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1> <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
 <20210514201808.GO975577@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20210514201808.GO975577@paulmck-ThinkPad-P17-Gen-1>
From: Arnd Bergmann <arnd@kernel.org>
Date: Fri, 14 May 2021 23:16:02 +0200
X-Gmail-Original-Message-ID: <CAK8P3a3O=DPgsXZpBxz+cPEHAzGaW+64GBDM4BMzAZQ+5w6Dow@mail.gmail.com>
Message-ID: <CAK8P3a3O=DPgsXZpBxz+cPEHAzGaW+64GBDM4BMzAZQ+5w6Dow@mail.gmail.com>
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Marco Elver <elver@google.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="oy/zU7SW";       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, May 14, 2021 at 10:18 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> On Fri, May 14, 2021 at 01:11:05PM -0700, Nathan Chancellor wrote:

> > You can see my response to Marco here:
> >
> > https://lore.kernel.org/r/ad7fa126-f371-5a24-1d80-27fe8f655b05@kernel.org/
> >
> > Maybe some improved wording might look like
> >
> > clang with CONFIG_LTO_CLANG points out that an initcall function should
> > return an 'int' due to the changes made to the initcall macros in commit
> > 3578ad11f3fb ("init: lto: fix PREL32 relocations"):
>
> OK, so the naive reading was correct, thank you!
>
> > ...
> >
> > Arnd, do you have any objections?
>
> In the meantime, here is what I have.  Please let me know of any needed
> updates.
>

Looks good to me, thanks for the improvements!

          Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a3O%3DDPgsXZpBxz%2BcPEHAzGaW%2B64GBDM4BMzAZQ%2B5w6Dow%40mail.gmail.com.
