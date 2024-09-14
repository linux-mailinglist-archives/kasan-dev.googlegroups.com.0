Return-Path: <kasan-dev+bncBCS4VDMYRUNBBAEKSW3QMGQEEZGQXQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 885A7978F01
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Sep 2024 10:10:43 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5e1c323b804sf499935eaf.2
        for <lists+kasan-dev@lfdr.de>; Sat, 14 Sep 2024 01:10:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726301440; cv=pass;
        d=google.com; s=arc-20240605;
        b=DFun+lIlaYX7drHZW5/6szzkfCVxnamsJWBF+SPEJAGKcAEemdqbU6oPIRKI7URz5E
         EBa23s/RmCz1XsNFGawyWTun1WGQY1aicsMchCw0j/VFIhtiNY6tGw+ciOv26FIOhZIE
         LGo6K7lWlSsaNKFiryFRvtfM5VMU7O1rVBAou8NXRp/P/0wQt+QHtQqknzgnOLvKT/y7
         OVhR8+T+50Co39iczXSxRqMmDVr4rz1y3y5yZaoUHGvk+0MgMvwyvCrYIsWU2co+5R0T
         DbvyC273BAxBh7EARTsRTFbiYnaV7tL7GTxc90VdkQb2h20RS70aFOcIxezFj4l78WS8
         +0PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=d2xbJGVcgT/bh9SzS2Hy139LdaWp8fBsiGA0Ylv/LJ8=;
        fh=r3Wjp3Iogy3EZXOfcC+vm1Na14bdb3aTs8YE36DL9Aw=;
        b=G5ZWbdz7wi4fnedpANhH0TZY9Ewh0aqKxoHvBP59XHSU+wvM3qQGERuRt8yXIze902
         O5Xs+GJ78jvUqJqAkdvy3N9JKiHG6+sD83bT2L2Pj7TtB6A7tBQ+anVTAirXHTFpOw8w
         bdyS4tneIe3Eqnt/De+i5yhLIaEoGRORxynKXfTjbYQU2EW849ZZre6b7ubSHdFcqFMg
         UAoZ3AKWK/1s0OpssFYSb7UUSYkA3Ox3lP2J+TMQAeIzDWYvJMPxjDKIRehpTfCwnbK4
         VW6jPX0LojxPfhrwgm8ydGFsncDvT6le87MrV9LpagUD4QdOXJlIidmELnAQ1iXUtfeH
         Yc3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NmaslCxb;
       spf=pass (google.com: domain of srs0=xvqu=qm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=XvQU=QM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726301440; x=1726906240; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d2xbJGVcgT/bh9SzS2Hy139LdaWp8fBsiGA0Ylv/LJ8=;
        b=QwkwbTmZ0aAmf9lZYBdzVnAv2A/rT3q4EDUNTzhUk56eEsoWeFmu1VAV+fCgpsB+6+
         Ex4YvJhStUrlFf5tTVsx5nM5dJtqLybxGxON+gwD0NEKozAj/iMl/9rgqgAwlsBfi1+y
         xCQgYuZgVsVy6ffbZ/13FH3LC41rAitFOiTFwmbwRZqm0ylCo7wjVY9/wtzzBz2p3RPQ
         xWBKfcH9C24lZyEWUOwgoSLiWGP0LPCUBqG+A3IYAo9UByC6qq6LQybnqBv2geBLlQEB
         PO1uIfcfUlCt6ED02m447vRrPTrYA9KmvC5QV3BMR1sBEUwLQyAb6VWdEhAj4yqL9jE5
         ebyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726301440; x=1726906240;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d2xbJGVcgT/bh9SzS2Hy139LdaWp8fBsiGA0Ylv/LJ8=;
        b=Jsr2zZvtHcFkJllPpGTB/AllfMIw3Uhn84Pg9iT3CdThv/oIOUB3oo5p9EaWRtnrpi
         7VdIulO2PGHNmlwny2ogMYMcoFCPjRvowY/qsWeIP+dxoVUAKwvYDqTBwujaJjAayS36
         hSmJCAWvynMTC1zy7sMo6X4EKt5Kavv280WrLnNt8w7MW8d/n/7cO3ofOWAgkyC351cY
         VKz9HgoCpvt9dKZIaU1twDvUjwJj7Fa+SzPdhbxCTD9Rb7w0gC99BagS9L8bchWLqSwI
         g7Qm1Kseh2dRZV7f5KPRwmslNeQlKWxzXX4acNaxfwFmRlBlLj/HG28DDu/om4GAjikl
         jC8A==
X-Forwarded-Encrypted: i=2; AJvYcCVOh2tdSAyHCDGvi2eZnyNia0i9DZTNBoxhEVUbWb/97WfvFADOijW73g4V+h1s6t6dNekhKA==@lfdr.de
X-Gm-Message-State: AOJu0YzK2C1ugRfluMGdIXmVM2S8bUD/ucl9Q1laV25+IYyNpM5YreLr
	hoQYpmutK3UP2+eY0BMEwkeFLaURo4XFQG0CCeJ56gJaoEjxUltZ
X-Google-Smtp-Source: AGHT+IFRcQM+o5xylKbd7S/1MGxmAqE7rWv6t6DWOokiJIcsnlSmn2ZGkkw/6qTCWENDNqFI3mDkbw==
X-Received: by 2002:a05:6808:3c99:b0:3e0:391f:dc7a with SMTP id 5614622812f47-3e07a16c907mr3073365b6e.34.1726301440428;
        Sat, 14 Sep 2024 01:10:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e9a4:0:b0:5e1:d935:e49e with SMTP id 006d021491bc7-5e200a80c44ls1201370eaf.2.-pod-prod-06-us;
 Sat, 14 Sep 2024 01:10:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAjhpMrO5UF00ufhHu3DzFz4GAuaHeYkztlNzOxF9/IgZReRXD/sA6oUYnG0c+AT1oXH29vRtgBvw=@googlegroups.com
X-Received: by 2002:a05:6830:dc5:b0:703:7827:6a68 with SMTP id 46e09a7af769-71116bb9264mr2499035a34.6.1726301439642;
        Sat, 14 Sep 2024 01:10:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726301439; cv=none;
        d=google.com; s=arc-20240605;
        b=kJ5kLRNMnx2kk2aAwWcVTDA0PqzDtZVgM/oiF9BM1g4r+qUWMnmC2qPFtzqysmAWqZ
         iiDsARwgTSZKGjcRNbBuT259uGdrGwEvpsPsJtW0VvAmuIE3+TYbsNAr29HaNPb50z2W
         PzpCHz8paha76XMA87afPZpKR3TcZSD0lr3ti3ug6+KvUP7yIgTZKqjzaGdeDrfNsdgt
         Htj2ge0YZYsZh2V6vwg3UZRURLPoZVuHVIGoLO/+/abyC3d0zO2NtCkfssaXVk/f4dSw
         wEmD3Ya4xMAJFWONZaTnwJGlJ75kbUcXA0yj27vKd7/G1gnnhaOG/4TJMPuHOoxuvxw+
         GU3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=8n1Zv+2tEMlNkTsM8bSfzgc7ioiyAJeIkYfUvWr7hYo=;
        fh=lcx2240/vlqXNJLIUUx/zjXi2mOSWqQHQHliRB+icXE=;
        b=BVwl6YjQRZ4pAXcdYCY42hMoWoPj4r3xvQY0j3cwcVZK69lubl7IdlozK6juoo5AGM
         57+gom63/x4L2Dc/89u2hYfhKNhJTwG6u6YhdjAw+NlIcfbC/+/WvozH/ESu6Kg0LZWg
         zCZzA3IeKoBzyaZ9I1a/5Ri5g3f6beSZPXlQAtwjh1UN+U8lrsmwtYLaYlhaSRFaRNiH
         uwKdyIBB3MYcVFec3cKICRZEkuKLdkpwv7yQwCZhULhbf05S6jGNJwANgE3qyAqDbU/j
         MFSHlratqLKQwN8pq5YxDlJF7ChtmtbqOEvS4t74UuIlQLm+H9+q5dl3Mb2BuUIFt+B3
         EfDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NmaslCxb;
       spf=pass (google.com: domain of srs0=xvqu=qm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=XvQU=QM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-71239f706cbsi37103a34.5.2024.09.14.01.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 14 Sep 2024 01:10:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xvqu=qm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B969B5C1054;
	Sat, 14 Sep 2024 08:10:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E1E10C4CEC0;
	Sat, 14 Sep 2024 08:10:38 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 56AA9CE0E7A; Sat, 14 Sep 2024 01:10:36 -0700 (PDT)
Date: Sat, 14 Sep 2024 01:10:36 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: torvalds@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@meta.com, elver@google.com, thorsten.blum@toblux.com
Subject: [GIT PULL] KCSAN changes for v6.12
Message-ID: <65bb8a3e-9d52-4f2a-9123-a4e310c88d10@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NmaslCxb;       spf=pass
 (google.com: domain of srs0=xvqu=qm=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=XvQU=QM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

Hello, Linus,

When the merge window opens, please pull the latest KCSAN git commit from:

  git://git.kernel.org/pub/scm/linux/kernel/git/paulmck/linux-rcu.git tags/kcsan.2024.09.14a
  # HEAD: 43d631bf06ec961bbe4c824b931fe03be44c419c: kcsan: Use min() to fix Coccinelle warning (2024-08-01 16:40:44 -0700)

----------------------------------------------------------------
kcsan: Use min() to fix Coccinelle warning.

Courtesy of Thorsten Blum.

----------------------------------------------------------------
Thorsten Blum (1):
      kcsan: Use min() to fix Coccinelle warning

 kernel/kcsan/debugfs.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/65bb8a3e-9d52-4f2a-9123-a4e310c88d10%40paulmck-laptop.
