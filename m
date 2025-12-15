Return-Path: <kasan-dev+bncBAABBLX477EQMGQERLEEOIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id CF22BCBDC5F
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 13:25:19 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-43009df5ab3sf750000f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 04:25:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765801519; cv=pass;
        d=google.com; s=arc-20240605;
        b=DEp2/6DnATP+pJ5dGLFAJaV3tLP+veIpwfEzgo2F7dUBYKpoGbOae8pePwX/CQoi5J
         /Aaic2A/OSk8CsPXSa35/QIhX5E0Nund7Ml9vwRlEZ89TI1NhlyBcpthQRyJK1nB49RT
         ctdm992hbgjnJEGbG2tyiLJwSl9FozYeJbi7MzAT5dop9esVShKXYtJUc8XM2TS82lPs
         AFpDszEv2dmkWFrsI57sH6VW02aLx1ja2qkaV+Pp4qswrcl6Sb/jyljMyKohZ2Hc2esz
         MLg5PnNZK5U/0AxYrtsFDQEz56Y8uTBYcuNdHxh/C6bd3cydN8GIG8YlaACiMiz9dQMw
         6N9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to
         :reply-to:from:subject:message-id:dkim-signature;
        bh=w7nVrFKjzYbzX8MqybplJdBkPFiu7/OgXi0gzC5ouvM=;
        fh=0PXGbjZmEJ3j/I129cHyIw1OzEpFzJs39P9IRSESY+k=;
        b=G0t+kb6QGdk//PbWd6sXhOvjvF+jOJUc0BwJqRfJa0gRcKdmETNe7h9vqJHYEiBXAh
         jcw9BbmhqytKDxcOgGQCnJMZ4ryIYoODABiE2tYf9IYMmeYRJ+ThbzkT14yCaYKop4oK
         x3oz+RsDCz0ME4MTMqOnofTRejfg2ZjxxhPnzGOqJRIHe/SU5yNTwpScERTzWMJH2ZQ3
         jzVNB4nGNNcA78svBLSsJW1+7kqFeV8sgK49nXPL+Mckl6KPLrsYIfXJZL1UlDm0iwl0
         T7lszfGCrleHsxVHAeYTEG4edC+sqIXmiX61CidZ3zGazrtWxJOoV40O7MVDND1XtPsQ
         FY+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mailbox.org header.s=mail20150812 header.b=MFNtC9o7;
       spf=pass (google.com: domain of phasta@mailbox.org designates 2001:67c:2050:0:465::202 as permitted sender) smtp.mailfrom=phasta@mailbox.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mailbox.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765801519; x=1766406319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:references
         :in-reply-to:date:cc:to:reply-to:from:subject:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=w7nVrFKjzYbzX8MqybplJdBkPFiu7/OgXi0gzC5ouvM=;
        b=iE5rP9Tn2rFhGNnxLzU10GxMh+E1C/1nPWQGjQIMbY2kDTnTbSdl5hLDYChusR9YWb
         aPxk0VmZXa8qRxrwkUC5LrSnRtha3xJmEo5b2anXTGtVA+VzThU+H1aYFSEpUAuJRans
         jZlsG9EzBUcYsqoEiEweGgyI2iJuDxaSwjZenRZyfmGWwROeeDvEe7TJdT5lVpVsHOJY
         40KHfJWhCwzy5Te39waKwTwGCvtc4OEguiuEUhqs9uAxDaUvco+eez+p9uZ/1SmRxdhJ
         h1Atr5gunMqz2C05uZIWh/VjC0oWoSyGvnNkvnPc/PQZarHbfYnZfIpCPsybVyka6KlE
         2e+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765801519; x=1766406319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to
         :reply-to:from:subject:message-id:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=w7nVrFKjzYbzX8MqybplJdBkPFiu7/OgXi0gzC5ouvM=;
        b=CVKwmycFiKBFgw0nvYJ+hIzT6EAVLPydr4OlXTsm/gwBxOI90PSw+4ocmlweTE7/YM
         O4ZmTp38O9RiChiVhOuDYo7Q4pFZNAD5J+aRq731gFDmB/FLenjJIBO4eX8yoPMpS1rs
         t9I8gn+j9875Rc/G6yRk0sO4VAhwsAiwYO+W4vrBnrATfUDAae9pXv2bicbpXJqrjBiL
         oOyENSfBP4DOO/m1WI8dHoHP/Y98hFN2bWu1fU+OIZ+MekLkll0VqE6u0VHyzo+8KA9V
         sO6BTAjMfq4NzoOGfMZTz/OO4qRp92d8iL0uW7ncqTd8cjmmTt1hYCYkzWhgD+zx9Mqe
         tfsQ==
X-Forwarded-Encrypted: i=2; AJvYcCXy8vP5mjfZ6xI2zTF0vhzct/MkDezNXNkP+0HKv/VNzYQ/PWpuUh2wl85CVAyZBL7npj2PYA==@lfdr.de
X-Gm-Message-State: AOJu0YyvWWFHVaTsgsQJg399XnJwHJ4sHzjHzGf6B6BK/iqBEaMvWLjd
	ohWIBq1bQSLZpkqqewz3P6BMM/JyVgXdh/JIoUAoZoSG8xVw6KTimeJ6
X-Google-Smtp-Source: AGHT+IG9Z8Nh97yzSpaaKqCntOD+97OEoUruqLCDJtM2OWqeNVwheeFxKUXJdyEgTU1U2/dXQ0QmLw==
X-Received: by 2002:a05:6000:2508:b0:42b:39ee:288e with SMTP id ffacd0b85a97d-42fb447ae72mr11978281f8f.13.1765801518901;
        Mon, 15 Dec 2025 04:25:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYsxR1p7YN/P93myYohhOUPFaony18RqfJZCvmfQV59Bg=="
Received: by 2002:a05:6000:144d:b0:42b:52c4:6610 with SMTP id
 ffacd0b85a97d-42fb2c59cd6ls1140946f8f.1.-pod-prod-01-eu; Mon, 15 Dec 2025
 04:25:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWZ6ppEbN2XF6LKttlkFRsy8H/mxHbjrLcACgiyyysMeSAFcNvmpSGH6dDrHOQNJiwiepjv9So4X4c=@googlegroups.com
X-Received: by 2002:a05:6000:2dca:b0:430:f3ab:56a1 with SMTP id ffacd0b85a97d-430f3ab58b0mr7062354f8f.42.1765801516785;
        Mon, 15 Dec 2025 04:25:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765801516; cv=none;
        d=google.com; s=arc-20240605;
        b=hJ89zkyirTVp+GclkHguAfppwBd6UA+Acu6QRSSpNuIwxis43Npu47ZY2Rb/o9cha0
         HBuuc5wkQHriWAd/fPL1r18VpFO3wyaEd+ne1fQk5c8Tx6gJkM35garcNY1+yBf26Ka6
         ARFoXnHGae3L0W/l3HKGZBf5q9/h3/RKDp5MjDXwxadPshjFRXksl5t7n8fr9AVYJKeO
         JDNTU0iCJ1+GVyHSANuM+P0EjtUAww3xBP6kqokrAiONByxuKHo5YuDDeR31JDP0m8Mm
         dH8lJ6uLZS8Gu1qstBlSvBsGA8GVGsaltyFhDBkSiiOLYwJ6/JSFJSY3aKrmGY+c369B
         dQLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:reply-to:from:subject:message-id:dkim-signature;
        bh=gJOFMp1/K+qQ0MSqjWn/CbbRaLJJuaP23xTo6CU3FMU=;
        fh=fBG2HCa+M+d3J+R8ZdX5UHhyONQMW2lStyOlPOv0/s0=;
        b=bDDdzjaP+9oXVBD+fOd77qCe+qasjkrjqwty05AIh0+Xuq+PWkmZ4375EuJYQYe5un
         KOS231V+lRlHup6gYJwdWQg+v1tx5ntOmzZT4dEanDnZBYE/Ts7IuRQMH9hySU8XKUP3
         KqL2r3xXwYwsXFlDVuPoMHNfh6mQJ/Mwx8wFRSUwytgakd3sBuCdMeyg+JyrPC0gMmKm
         GISHecK06aQi9FCzrrnI7Ig1xTl7yd3+8bc5Uc7YE6JRVTHeGwABp8txoaqWaSKSc9Sj
         gXHayfwFYqoGD+pNREIIrBWn8U74HAye0Ep612+gQw60ed6z6k0lGaFX2Z+Ct2nwfacz
         Vqlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mailbox.org header.s=mail20150812 header.b=MFNtC9o7;
       spf=pass (google.com: domain of phasta@mailbox.org designates 2001:67c:2050:0:465::202 as permitted sender) smtp.mailfrom=phasta@mailbox.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mailbox.org
Received: from mout-p-202.mailbox.org (mout-p-202.mailbox.org. [2001:67c:2050:0:465::202])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42fb583a47bsi201935f8f.8.2025.12.15.04.25.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 04:25:16 -0800 (PST)
Received-SPF: pass (google.com: domain of phasta@mailbox.org designates 2001:67c:2050:0:465::202 as permitted sender) client-ip=2001:67c:2050:0:465::202;
Received: from smtp2.mailbox.org (smtp2.mailbox.org [IPv6:2001:67c:2050:b231:465::2])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mout-p-202.mailbox.org (Postfix) with ESMTPS id 4dVK5Q3jjHz9t0N;
	Mon, 15 Dec 2025 13:25:14 +0100 (CET)
Message-ID: <1f0fd860bf3466b9967d5a99ecd49eb93e0f7a19.camel@mailbox.org>
Subject: Re: [PATCH 12/14] drm/scheduler: Describe @result in
 drm_sched_job_done()
From: "'Philipp Stanner' via kasan-dev" <kasan-dev@googlegroups.com>
Reply-To: phasta@kernel.org
To: Bagas Sanjaya <bagasdotme@gmail.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux AMDGPU
 <amd-gfx@lists.freedesktop.org>,  Linux DRI Development
 <dri-devel@lists.freedesktop.org>, Linux Filesystems Development
 <linux-fsdevel@vger.kernel.org>,  Linux Media
 <linux-media@vger.kernel.org>, linaro-mm-sig@lists.linaro.org,
 kasan-dev@googlegroups.com,  Linux Virtualization
 <virtualization@lists.linux.dev>, Linux Memory Management List
 <linux-mm@kvack.org>, Linux Network Bridge <bridge@lists.linux.dev>, Linux
 Networking <netdev@vger.kernel.org>
Cc: Harry Wentland <harry.wentland@amd.com>, Leo Li <sunpeng.li@amd.com>, 
 Rodrigo Siqueira <siqueira@igalia.com>, Alex Deucher
 <alexander.deucher@amd.com>, Christian =?ISO-8859-1?Q?K=F6nig?=
 <christian.koenig@amd.com>, David Airlie <airlied@gmail.com>, Simona Vetter
 <simona@ffwll.ch>, Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, 
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann
 <tzimmermann@suse.de>, Matthew Brost <matthew.brost@intel.com>, Danilo
 Krummrich <dakr@kernel.org>, Philipp Stanner <phasta@kernel.org>, Alexander
 Viro <viro@zeniv.linux.org.uk>, Christian Brauner <brauner@kernel.org>, Jan
 Kara <jack@suse.cz>, Sumit Semwal <sumit.semwal@linaro.org>,  Alexander
 Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, "Michael S. Tsirkin" <mst@redhat.com>, Jason
 Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>, Eugenio
 =?ISO-8859-1?Q?P=E9rez?= <eperezma@redhat.com>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Nikolay
 Aleksandrov <razor@blackwall.org>, Ido Schimmel <idosch@nvidia.com>, "David
 S. Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, Jakub
 Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, Simon Horman
 <horms@kernel.org>, Taimur Hassan <Syed.Hassan@amd.com>, Wayne Lin
 <Wayne.Lin@amd.com>, Alex Hung <alex.hung@amd.com>, Aurabindo Pillai
 <aurabindo.pillai@amd.com>, Dillon Varone <Dillon.Varone@amd.com>, George
 Shen <george.shen@amd.com>, Aric Cyr <aric.cyr@amd.com>, Cruise Hung
 <Cruise.Hung@amd.com>, Mario Limonciello <mario.limonciello@amd.com>, Sunil
 Khatri <sunil.khatri@amd.com>, Dominik Kaszewski
 <dominik.kaszewski@amd.com>, David Hildenbrand <david@kernel.org>, Peter
 Zijlstra <peterz@infradead.org>, Lorenzo Stoakes
 <lorenzo.stoakes@oracle.com>, Max Kellermann <max.kellermann@ionos.com>,
 "Nysal Jan K.A." <nysal@linux.ibm.com>, Ryan Roberts
 <ryan.roberts@arm.com>, Alexey Skidanov <alexey.skidanov@intel.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Kent Overstreet
 <kent.overstreet@linux.dev>, Vitaly Wool <vitaly.wool@konsulko.se>, Harry
 Yoo <harry.yoo@oracle.com>, Mateusz Guzik <mjguzik@gmail.com>, NeilBrown
 <neil@brown.name>, Amir Goldstein <amir73il@gmail.com>, Jeff Layton
 <jlayton@kernel.org>, Ivan Lipski <ivan.lipski@amd.com>, Tao Zhou
 <tao.zhou1@amd.com>, YiPeng Chai <YiPeng.Chai@amd.com>, Hawking Zhang
 <Hawking.Zhang@amd.com>, Lyude Paul <lyude@redhat.com>, Daniel Almeida
 <daniel.almeida@collabora.com>, Luben Tuikov <luben.tuikov@amd.com>,
 Matthew Auld <matthew.auld@intel.com>, Roopa Prabhu
 <roopa@cumulusnetworks.com>, Mao Zhu <zhumao001@208suo.com>, Shaomin Deng
 <dengshaomin@cdjrlc.com>, Charles Han <hanchunchao@inspur.com>, Jilin Yuan
 <yuanjilin@cdjrlc.com>, Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
 George Anthony Vernon <contact@gvernon.com>
Date: Mon, 15 Dec 2025 13:24:46 +0100
In-Reply-To: <20251215113903.46555-13-bagasdotme@gmail.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
	 <20251215113903.46555-13-bagasdotme@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MBO-RS-ID: 550cff02d5c77f160e4
X-MBO-RS-META: q9aiurnjorghwoz79fww7b6wqkkf5zeq
X-Original-Sender: phasta@mailbox.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mailbox.org header.s=mail20150812 header.b=MFNtC9o7;       spf=pass
 (google.com: domain of phasta@mailbox.org designates 2001:67c:2050:0:465::202
 as permitted sender) smtp.mailfrom=phasta@mailbox.org;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=mailbox.org
X-Original-From: Philipp Stanner <phasta@mailbox.org>
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

nit about commit title:
We use "drm/sched:" as prefix nowadays

On Mon, 2025-12-15 at 18:39 +0700, Bagas Sanjaya wrote:
> Sphinx reports kernel-doc warning:
>=20
> WARNING: ./drivers/gpu/drm/scheduler/sched_main.c:367 function parameter =
'result' not described in 'drm_sched_job_done'
>=20
> Describe @result parameter to fix it
>=20

Thx for fixing this!

> .
>=20
> Fixes: 539f9ee4b52a8b ("drm/scheduler: properly forward fence errors")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---
> =C2=A0drivers/gpu/drm/scheduler/sched_main.c | 1 +
> =C2=A01 file changed, 1 insertion(+)
>=20
> diff --git a/drivers/gpu/drm/scheduler/sched_main.c b/drivers/gpu/drm/sch=
eduler/sched_main.c
> index 1d4f1b822e7b76..4f844087fd48eb 100644
> --- a/drivers/gpu/drm/scheduler/sched_main.c
> +++ b/drivers/gpu/drm/scheduler/sched_main.c
> @@ -361,6 +361,7 @@ static void drm_sched_run_free_queue(struct drm_gpu_s=
cheduler *sched)
> =C2=A0/**
> =C2=A0 * drm_sched_job_done - complete a job
> =C2=A0 * @s_job: pointer to the job which is done
> + * @result: job result

"error code for the job's finished-fence" would be a bit better and
more verbose.

With that:

Reviewed-by: Philipp Stanner <phasta@kernel.org>

> =C2=A0 *
> =C2=A0 * Finish the job's fence and resubmit the work items.
> =C2=A0 */

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
f0fd860bf3466b9967d5a99ecd49eb93e0f7a19.camel%40mailbox.org.
